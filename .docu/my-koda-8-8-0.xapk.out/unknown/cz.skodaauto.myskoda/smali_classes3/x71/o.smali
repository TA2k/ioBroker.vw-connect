.class public final Lx71/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# static fields
.field public static final d:Lx71/o;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lx71/o;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx71/o;->d:Lx71/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 2

    .line 1
    check-cast p1, Lx71/f;

    .line 2
    .line 3
    check-cast p2, Lx71/f;

    .line 4
    .line 5
    const-string p0, "a"

    .line 6
    .line 7
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string p0, "b"

    .line 11
    .line 12
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p2, Lx71/f;->c:Lx71/h;

    .line 16
    .line 17
    iget-wide v0, p0, Lx71/h;->b:J

    .line 18
    .line 19
    iget-object p0, p1, Lx71/f;->c:Lx71/h;

    .line 20
    .line 21
    iget-wide p0, p0, Lx71/h;->b:J

    .line 22
    .line 23
    sub-long/2addr v0, p0

    .line 24
    const-wide/16 p0, 0x0

    .line 25
    .line 26
    cmp-long p0, v0, p0

    .line 27
    .line 28
    if-lez p0, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :cond_0
    if-gez p0, :cond_1

    .line 33
    .line 34
    const/4 p0, -0x1

    .line 35
    return p0

    .line 36
    :cond_1
    const/4 p0, 0x0

    .line 37
    return p0
.end method
