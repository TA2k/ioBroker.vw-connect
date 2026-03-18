.class public final Lorg/altbeacon/beacon/logging/Loggers;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final API_TRACKING_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/ApiTrackingLogger;

.field private static final EMPTY_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

.field private static final INFO_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

.field private static final VERBOSE_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

.field private static final WARNING_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/logging/EmptyLogger;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/logging/EmptyLogger;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/logging/Loggers;->EMPTY_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 7
    .line 8
    new-instance v0, Lorg/altbeacon/beacon/logging/VerboseAndroidLogger;

    .line 9
    .line 10
    invoke-direct {v0}, Lorg/altbeacon/beacon/logging/VerboseAndroidLogger;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lorg/altbeacon/beacon/logging/Loggers;->VERBOSE_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 14
    .line 15
    new-instance v0, Lorg/altbeacon/beacon/logging/InfoAndroidLogger;

    .line 16
    .line 17
    invoke-direct {v0}, Lorg/altbeacon/beacon/logging/InfoAndroidLogger;-><init>()V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lorg/altbeacon/beacon/logging/Loggers;->INFO_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 21
    .line 22
    new-instance v0, Lorg/altbeacon/beacon/logging/WarningAndroidLogger;

    .line 23
    .line 24
    invoke-direct {v0}, Lorg/altbeacon/beacon/logging/WarningAndroidLogger;-><init>()V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lorg/altbeacon/beacon/logging/Loggers;->WARNING_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 28
    .line 29
    new-instance v0, Lorg/altbeacon/beacon/logging/ApiTrackingLogger;

    .line 30
    .line 31
    invoke-direct {v0}, Lorg/altbeacon/beacon/logging/ApiTrackingLogger;-><init>()V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lorg/altbeacon/beacon/logging/Loggers;->API_TRACKING_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/ApiTrackingLogger;

    .line 35
    .line 36
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static apiTrackingLogger()Lorg/altbeacon/beacon/logging/ApiTrackingLogger;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/Loggers;->API_TRACKING_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/ApiTrackingLogger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static empty()Lorg/altbeacon/beacon/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/Loggers;->EMPTY_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static infoLogger()Lorg/altbeacon/beacon/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/Loggers;->INFO_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static verboseLogger()Lorg/altbeacon/beacon/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/Loggers;->VERBOSE_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static warningLogger()Lorg/altbeacon/beacon/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/Loggers;->WARNING_ANDROID_LOGGER:Lorg/altbeacon/beacon/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method
