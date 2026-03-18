.class public final Law0/f;
.super Law0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Z


# direct methods
.method public constructor <init>(Lzv0/c;Lkw0/b;Law0/h;[B)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Law0/c;-><init>(Lzv0/c;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Law0/g;

    .line 5
    .line 6
    invoke-direct {p1, p0, p2}, Law0/g;-><init>(Law0/f;Lkw0/b;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Law0/c;->e:Lkw0/b;

    .line 10
    .line 11
    new-instance p1, Law0/h;

    .line 12
    .line 13
    invoke-direct {p1, p0, p4, p3}, Law0/h;-><init>(Law0/f;[BLaw0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Law0/c;->f:Law0/h;

    .line 17
    .line 18
    invoke-static {p3}, Ljp/pc;->b(Law0/h;)Ljava/lang/Long;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    array-length p3, p4

    .line 23
    int-to-long p3, p3

    .line 24
    invoke-interface {p2}, Lkw0/b;->getMethod()Low0/s;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    invoke-static {p1, p3, p4, p2}, Ljp/p1;->a(Ljava/lang/Long;JLow0/s;)V

    .line 29
    .line 30
    .line 31
    const/4 p1, 0x1

    .line 32
    iput-boolean p1, p0, Law0/f;->i:Z

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final b()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Law0/f;->i:Z

    .line 2
    .line 3
    return p0
.end method
