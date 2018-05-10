ENABLE_STATIC_LIB=0
ENABLE_SHARED_LIB=1

TARGET_PREFIX=$DESTDIR/usr/local
TARGET_CONF_PATH=$DESTDIR/etc/mc

DEBUG_FLAG=1

CFLAGS="$CFLAGS -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE"
if [ "$DEBUG_FLAG" = "1" ]; then
  CFLAGS="$CFLAGS -g -O1 -DDEBUG_FLAG"
else
  CFLAGS="$CFLAGS -O3"
fi

LIBS=''
uname=$(uname)
if [ "$uname" = "Linux" ]; then
  CFLAGS="$CFLAGS"
elif [ "$uname" = "FreeBSD" ]; then
  CFLAGS="$CFLAGS"
elif [ "$uname" = "SunOS" ]; then
  CFLAGS="$CFLAGS -D_THREAD_SAFE"
  LIBS="$LIBS -lsocket -lnsl -lresolv"
  export CC=gcc
elif [ "$uname" = "AIX" ]; then
  CFLAGS="$CFLAGS -D_THREAD_SAFE"
  export CC=gcc
elif [ "$uname" = "HP-UX" ]; then
  CFLAGS="$CFLAGS"
fi

have_pthread=0
if [ -f /usr/lib/libpthread.so ] || [ -f /usr/local/lib/libpthread.so ] || [ -f /lib64/libpthread.so ] || [ -f /usr/lib64/libpthread.so ] || [ -f /usr/lib/libpthread.a ] || [ -f /usr/local/lib/libpthread.a ] || [ -f /lib64/libpthread.a ] || [ -f /usr/lib64/libpthread.a ]; then
  LIBS="$LIBS -lpthread"
  have_pthread=1
elif [ "$uname" = "HP-UX" ]; then
  lib_path="/usr/lib/hpux$OS_BITS"
  if [ -f $lib_path/libpthread.so ]; then
    LIBS="-L$lib_path -lpthread"
    have_pthread=1
  fi
elif [ "$uname" = "FreeBSD" ]; then
  if [ -f /usr/lib/libc_r.so ]; then
    line=$(nm -D /usr/lib/libc_r.so | grep pthread_create | grep -w T)
    if [ $? -eq 0 ]; then
      LIBS="$LIBS -lc_r"
      have_pthread=1
    fi
  elif [ -f /lib64/libc_r.so ]; then
    line=$(nm -D /lib64/libc_r.so | grep pthread_create | grep -w T)
    if [ $? -eq 0 ]; then
      LIBS="$LIBS -lc_r"
      have_pthread=1
    fi
  elif [ -f /usr/lib64/libc_r.so ]; then
    line=$(nm -D /usr/lib64/libc_r.so | grep pthread_create | grep -w T)
    if [ $? -eq 0 ]; then
      LIBS="$LIBS -lc_r"
      have_pthread=1
    fi
  fi
fi

if [ $have_pthread -eq 0 ] && [ "$uname" = "Linux" ]; then
   /sbin/ldconfig -p | fgrep libpthread.so > /dev/null
   if [ $? -eq 0 ]; then
      LIBS="$LIBS -lpthread"
   else
      echo -E 'Require pthread lib, please check!'
      exit 2
   fi
fi

if [ "$DEBUG_FLAG" = "1" ]; then
  if [ "$uname" = "Linux" ]; then
    LIBS="$LIBS -ldl -rdynamic"
  fi
fi

sed_replace()
{
    sed_cmd=$1
    filename=$2
    if [ "$uname" = "FreeBSD" ] || [ "$uname" = "Darwin" ]; then
       sed -i "" "$sed_cmd" $filename
    else
       sed -i "$sed_cmd" $filename
    fi
}

cd src
cp Makefile.in Makefile
sed_replace "s#\$(CFLAGS)#$CFLAGS#g" Makefile
sed_replace "s#\$(LIBS)#$LIBS#g" Makefile
sed_replace "s#\$(TARGET_PREFIX)#$TARGET_PREFIX#g" Makefile
sed_replace "s#\$(ENABLE_STATIC_LIB)#$ENABLE_STATIC_LIB#g" Makefile
sed_replace "s#\$(ENABLE_SHARED_LIB)#$ENABLE_SHARED_LIB#g" Makefile
make $1 $2

