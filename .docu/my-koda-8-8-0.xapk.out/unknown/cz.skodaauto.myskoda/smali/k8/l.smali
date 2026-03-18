.class public final Lk8/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lin/p;

.field public static final e:Lin/p;


# instance fields
.field public final a:Ll8/a;

.field public b:Lk8/i;

.field public c:Ljava/io/IOException;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lin/p;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    invoke-direct {v0, v1, v2, v3}, Lin/p;-><init>(IJ)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lk8/l;->d:Lin/p;

    .line 13
    .line 14
    new-instance v0, Lin/p;

    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    invoke-direct {v0, v1, v2, v3}, Lin/p;-><init>(IJ)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lk8/l;->e:Lin/p;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>(Ll8/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk8/l;->a:Ll8/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lk8/l;->b:Lk8/i;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method
