.class public final Lko/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lko/h;


# instance fields
.field public final a:Llo/a;

.field public final b:Landroid/os/Looper;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Llo/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    new-instance v2, Lko/h;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lko/h;-><init>(Llo/a;Landroid/os/Looper;)V

    .line 13
    .line 14
    .line 15
    sput-object v2, Lko/h;->c:Lko/h;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Llo/a;Landroid/os/Looper;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lko/h;->a:Llo/a;

    .line 5
    .line 6
    iput-object p2, p0, Lko/h;->b:Landroid/os/Looper;

    .line 7
    .line 8
    return-void
.end method
