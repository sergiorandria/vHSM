#pragma once

#include <mutex>
#include <utility>

namespace vhsm::threadpool {

    // CRTP singleton base.  A derived type T exposes:
    //     T& instance(Args&&... args)   -> process-wide instance, built on first use
    //     void reset()                  -> destroys the instance (dtor runs)
    // The first call to instance() constructs T with the forwarded arguments; later
    // calls (including calls with different arguments) return the existing object.
    //
    // A derived type grants construction access by declaring the friend:
    //     friend class ISingleton<Derived>;
    template <typename T>
    class ISingleton {
    public:
        ISingleton() = default;
        virtual ~ISingleton() = default;

        ISingleton(const ISingleton&) = delete;
        ISingleton& operator=(const ISingleton&) = delete;

        template <typename... Args>
        static T& instance(Args&&... args);

        static void reset();

    private:
        static T*& slot()
        {
            static T* instance_ptr = nullptr;
            return instance_ptr;
        }

        static std::mutex& lifecycle_mutex()
        {
            static std::mutex mtx;
            return mtx;
        }
    };

    template <typename T>
    template <typename... Args>
    T& ISingleton<T>::instance(Args&&... args)
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex());
        T*& ptr = slot();
        if (ptr == nullptr)
            ptr = new T(std::forward<Args>(args)...);
        return *ptr;
    }

    template <typename T>
    void ISingleton<T>::reset()
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex());
        T*& ptr = slot();
        T* old = ptr;
        ptr = nullptr;
        delete old;
    }

} // namespace vhsm::threadpool