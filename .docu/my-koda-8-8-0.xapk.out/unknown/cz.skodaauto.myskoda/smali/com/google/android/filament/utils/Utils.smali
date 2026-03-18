.class public final Lcom/google/android/filament/utils/Utils;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u00c6\u0002\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\r\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0005\u0010\u0003\u00a8\u0006\u0006"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Utils;",
        "",
        "<init>",
        "()V",
        "Llx0/b0;",
        "init",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final INSTANCE:Lcom/google/android/filament/utils/Utils;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Utils;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/filament/utils/Utils;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/filament/utils/Utils;->INSTANCE:Lcom/google/android/filament/utils/Utils;

    .line 7
    .line 8
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


# virtual methods
.method public final init()V
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/Filament;->init()V

    .line 2
    .line 3
    .line 4
    const-string p0, "filament-utils-jni"

    .line 5
    .line 6
    invoke-static {p0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method
