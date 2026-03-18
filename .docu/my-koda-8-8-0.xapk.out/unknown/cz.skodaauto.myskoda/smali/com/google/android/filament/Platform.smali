.class abstract Lcom/google/android/filament/Platform;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Platform$UnknownPlatform;
    }
.end annotation


# static fields
.field private static mCurrentPlatform:Lcom/google/android/filament/Platform;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static get()Lcom/google/android/filament/Platform;
    .locals 2

    .line 1
    sget-object v0, Lcom/google/android/filament/Platform;->mCurrentPlatform:Lcom/google/android/filament/Platform;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    :try_start_0
    invoke-static {}, Lcom/google/android/filament/Platform;->isAndroid()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const-class v0, Lcom/google/android/filament/AndroidPlatform;

    .line 12
    .line 13
    sget v1, Lcom/google/android/filament/AndroidPlatform;->a:I

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lcom/google/android/filament/Platform;

    .line 20
    .line 21
    sput-object v0, Lcom/google/android/filament/Platform;->mCurrentPlatform:Lcom/google/android/filament/Platform;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const-string v0, "com.google.android.filament.DesktopPlatform"

    .line 25
    .line 26
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Lcom/google/android/filament/Platform;

    .line 35
    .line 36
    sput-object v0, Lcom/google/android/filament/Platform;->mCurrentPlatform:Lcom/google/android/filament/Platform;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    :catch_0
    :goto_0
    sget-object v0, Lcom/google/android/filament/Platform;->mCurrentPlatform:Lcom/google/android/filament/Platform;

    .line 39
    .line 40
    if-nez v0, :cond_1

    .line 41
    .line 42
    new-instance v0, Lcom/google/android/filament/Platform$UnknownPlatform;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    invoke-direct {v0, v1}, Lcom/google/android/filament/Platform$UnknownPlatform;-><init>(I)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lcom/google/android/filament/Platform;->mCurrentPlatform:Lcom/google/android/filament/Platform;

    .line 49
    .line 50
    :cond_1
    sget-object v0, Lcom/google/android/filament/Platform;->mCurrentPlatform:Lcom/google/android/filament/Platform;

    .line 51
    .line 52
    return-object v0
.end method

.method public static isAndroid()Z
    .locals 2

    .line 1
    const-string v0, "java.vendor"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "The Android Project"

    .line 8
    .line 9
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    return v0
.end method

.method public static isLinux()Z
    .locals 2

    .line 1
    const-string v0, "os.name"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "Linux"

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-static {}, Lcom/google/android/filament/Platform;->isAndroid()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x1

    .line 22
    return v0

    .line 23
    :cond_0
    const/4 v0, 0x0

    .line 24
    return v0
.end method

.method public static isMacOS()Z
    .locals 2

    .line 1
    const-string v0, "os.name"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "Mac OS X"

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    return v0
.end method

.method public static isWindows()Z
    .locals 2

    .line 1
    const-string v0, "os.name"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "Windows"

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    return v0
.end method


# virtual methods
.method public abstract getSharedContextNativeHandle(Ljava/lang/Object;)J
.end method

.method public abstract log(Ljava/lang/String;)V
.end method

.method public abstract validateSharedContext(Ljava/lang/Object;)Z
.end method

.method public abstract validateStreamSource(Ljava/lang/Object;)Z
.end method

.method public abstract validateSurface(Ljava/lang/Object;)Z
.end method

.method public abstract warn(Ljava/lang/String;)V
.end method
