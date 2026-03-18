.class public abstract Leb/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Landroidx/work/WorkerParameters;

.field public final f:Ljava/util/concurrent/atomic/AtomicInteger;

.field public g:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 5
    .line 6
    const/16 v1, -0x100

    .line 7
    .line 8
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Leb/v;->f:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 12
    .line 13
    iput-object p1, p0, Leb/v;->d:Landroid/content/Context;

    .line 14
    .line 15
    iput-object p2, p0, Leb/v;->e:Landroidx/work/WorkerParameters;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public abstract a()Ly4/k;
.end method

.method public abstract c()Ly4/k;
.end method
