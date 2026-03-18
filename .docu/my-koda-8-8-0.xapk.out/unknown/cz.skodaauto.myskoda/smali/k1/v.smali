.class public final Lk1/v;
.super Lk1/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Lk1/a;


# direct methods
.method public constructor <init>(Lk1/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk1/v;->i:Lk1/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final e(ILt4/m;Lt3/e1;I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lk1/v;->i:Lk1/a;

    .line 2
    .line 3
    iget-object p0, p0, Lk1/a;->a:Lt3/a;

    .line 4
    .line 5
    invoke-virtual {p3, p0}, Lt3/e1;->a0(Lt3/a;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const/high16 p3, -0x80000000

    .line 10
    .line 11
    if-eq p0, p3, :cond_1

    .line 12
    .line 13
    sub-int/2addr p4, p0

    .line 14
    sget-object p0, Lt4/m;->e:Lt4/m;

    .line 15
    .line 16
    if-ne p2, p0, :cond_0

    .line 17
    .line 18
    sub-int/2addr p1, p4

    .line 19
    return p1

    .line 20
    :cond_0
    return p4

    .line 21
    :cond_1
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final f(Lt3/e1;)Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lk1/v;->i:Lk1/a;

    .line 2
    .line 3
    iget-object p0, p0, Lk1/a;->a:Lt3/a;

    .line 4
    .line 5
    invoke-virtual {p1, p0}, Lt3/e1;->a0(Lt3/a;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
