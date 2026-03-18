.class public final Lo1/n;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu3/e;
.implements Lv3/y;


# static fields
.field public static final v:Lo1/l;


# instance fields
.field public r:Lo1/o;

.field public s:Lg1/r;

.field public t:Z

.field public u:Lg1/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lo1/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lo1/n;->v:Lo1/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final G()Llp/e1;
    .locals 2

    .line 1
    sget-object v0, Lt3/g;->a:Lu3/h;

    .line 2
    .line 3
    new-instance v1, Lu3/i;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Lu3/i;-><init>(Lu3/h;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, v1, Lu3/i;->b:Ll2/j1;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-object v1
.end method

.method public final X0(Lo1/k;I)Z
    .locals 3

    .line 1
    const/4 v0, 0x5

    .line 2
    const/4 v1, 0x1

    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 v0, 0x6

    .line 7
    if-ne p2, v0, :cond_1

    .line 8
    .line 9
    :goto_0
    iget-object v0, p0, Lo1/n;->u:Lg1/w1;

    .line 10
    .line 11
    sget-object v2, Lg1/w1;->e:Lg1/w1;

    .line 12
    .line 13
    if-ne v0, v2, :cond_5

    .line 14
    .line 15
    goto :goto_4

    .line 16
    :cond_1
    const/4 v0, 0x3

    .line 17
    if-ne p2, v0, :cond_2

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_2
    const/4 v0, 0x4

    .line 21
    if-ne p2, v0, :cond_3

    .line 22
    .line 23
    :goto_1
    iget-object v0, p0, Lo1/n;->u:Lg1/w1;

    .line 24
    .line 25
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 26
    .line 27
    if-ne v0, v2, :cond_5

    .line 28
    .line 29
    goto :goto_4

    .line 30
    :cond_3
    if-ne p2, v1, :cond_4

    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_4
    const/4 v0, 0x2

    .line 34
    if-ne p2, v0, :cond_8

    .line 35
    .line 36
    :cond_5
    :goto_2
    invoke-virtual {p0, p2}, Lo1/n;->Y0(I)Z

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    if-eqz p2, :cond_6

    .line 41
    .line 42
    iget p1, p1, Lo1/k;->b:I

    .line 43
    .line 44
    iget-object p0, p0, Lo1/n;->r:Lo1/o;

    .line 45
    .line 46
    invoke-interface {p0}, Lo1/o;->a()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    sub-int/2addr p0, v1

    .line 51
    if-ge p1, p0, :cond_7

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_6
    iget p0, p1, Lo1/k;->a:I

    .line 55
    .line 56
    if-lez p0, :cond_7

    .line 57
    .line 58
    :goto_3
    return v1

    .line 59
    :cond_7
    :goto_4
    const/4 p0, 0x0

    .line 60
    return p0

    .line 61
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string p1, "Lazy list does not support beyond bounds layout for the specified direction"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
.end method

.method public final Y0(I)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, v0, :cond_0

    .line 3
    .line 4
    goto :goto_1

    .line 5
    :cond_0
    const/4 v1, 0x2

    .line 6
    if-ne p1, v1, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    const/4 v1, 0x5

    .line 10
    if-ne p1, v1, :cond_2

    .line 11
    .line 12
    iget-boolean p0, p0, Lo1/n;->t:Z

    .line 13
    .line 14
    return p0

    .line 15
    :cond_2
    const/4 v1, 0x6

    .line 16
    if-ne p1, v1, :cond_3

    .line 17
    .line 18
    iget-boolean p0, p0, Lo1/n;->t:Z

    .line 19
    .line 20
    if-nez p0, :cond_9

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_3
    const/4 v1, 0x3

    .line 24
    if-ne p1, v1, :cond_6

    .line 25
    .line 26
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iget-object p1, p1, Lv3/h0;->B:Lt4/m;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-eqz p1, :cond_5

    .line 37
    .line 38
    if-ne p1, v0, :cond_4

    .line 39
    .line 40
    iget-boolean p0, p0, Lo1/n;->t:Z

    .line 41
    .line 42
    if-nez p0, :cond_9

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_4
    new-instance p0, La8/r0;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_5
    iget-boolean p0, p0, Lo1/n;->t:Z

    .line 52
    .line 53
    return p0

    .line 54
    :cond_6
    const/4 v1, 0x4

    .line 55
    if-ne p1, v1, :cond_a

    .line 56
    .line 57
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    iget-object p1, p1, Lv3/h0;->B:Lt4/m;

    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_8

    .line 68
    .line 69
    if-ne p1, v0, :cond_7

    .line 70
    .line 71
    iget-boolean p0, p0, Lo1/n;->t:Z

    .line 72
    .line 73
    return p0

    .line 74
    :cond_7
    new-instance p0, La8/r0;

    .line 75
    .line 76
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_8
    iget-boolean p0, p0, Lo1/n;->t:Z

    .line 81
    .line 82
    if-nez p0, :cond_9

    .line 83
    .line 84
    :goto_0
    return v0

    .line 85
    :cond_9
    :goto_1
    const/4 p0, 0x0

    .line 86
    return p0

    .line 87
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 88
    .line 89
    const-string p1, "Lazy list does not support beyond bounds layout for the specified direction"

    .line 90
    .line 91
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p0
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 1

    .line 1
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget p2, p0, Lt3/e1;->d:I

    .line 6
    .line 7
    iget p3, p0, Lt3/e1;->e:I

    .line 8
    .line 9
    new-instance p4, Lam/a;

    .line 10
    .line 11
    const/16 v0, 0x11

    .line 12
    .line 13
    invoke-direct {p4, p0, v0}, Lam/a;-><init>(Lt3/e1;I)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 17
    .line 18
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
