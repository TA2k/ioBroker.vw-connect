.class public final Ly4/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ly4/c;


# instance fields
.field public final a:Ljava/lang/Runnable;

.field public final b:Ljava/util/concurrent/Executor;

.field public c:Ly4/c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ly4/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Ly4/c;-><init>(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ly4/c;->d:Ly4/c;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Ly4/c;->a:Ljava/lang/Runnable;

    .line 5
    .line 6
    iput-object p1, p0, Ly4/c;->b:Ljava/util/concurrent/Executor;

    .line 7
    .line 8
    return-void
.end method
