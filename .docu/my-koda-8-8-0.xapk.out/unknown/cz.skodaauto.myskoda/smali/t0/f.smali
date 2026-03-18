.class public final Lt0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/o2;
.implements Lh0/a1;
.implements Ll0/l;


# static fields
.field public static final e:Lh0/g;


# instance fields
.field public final d:Lh0/n1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh0/g;

    .line 2
    .line 3
    const-string v1, "camerax.core.streamSharing.captureTypes"

    .line 4
    .line 5
    const-class v2, Ljava/util/List;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v0, v1, v2, v3}, Lh0/g;-><init>(Ljava/lang/String;Ljava/lang/Class;Landroid/hardware/camera2/CaptureRequest$Key;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lt0/f;->e:Lh0/g;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lh0/n1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt0/f;->d:Lh0/n1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final p()Lh0/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lt0/f;->d:Lh0/n1;

    .line 2
    .line 3
    return-object p0
.end method
