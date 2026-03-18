.class public abstract Lb1/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/f1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x7

    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-static {v2, v2, v0, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lb1/a1;->a:Lc1/f1;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;
    .locals 9

    .line 1
    and-int/lit8 v0, p6, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p2, Lb1/a1;->a:Lc1/f1;

    .line 6
    .line 7
    :cond_0
    move-object v2, p2

    .line 8
    and-int/lit8 p2, p6, 0x4

    .line 9
    .line 10
    if-eqz p2, :cond_1

    .line 11
    .line 12
    const-string p3, "ColorAnimation"

    .line 13
    .line 14
    :cond_1
    move-object v4, p3

    .line 15
    invoke-static {p0, p1}, Le3/s;->f(J)Lf3/c;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    move-object v6, p4

    .line 20
    check-cast v6, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {v6, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p3

    .line 30
    if-nez p2, :cond_2

    .line 31
    .line 32
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 33
    .line 34
    if-ne p3, p2, :cond_3

    .line 35
    .line 36
    :cond_2
    invoke-static {p0, p1}, Le3/s;->f(J)Lf3/c;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    sget-object p3, Lb1/c;->l:Lb1/c;

    .line 41
    .line 42
    new-instance p4, La3/f;

    .line 43
    .line 44
    const/4 p6, 0x7

    .line 45
    invoke-direct {p4, p2, p6}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    new-instance p2, Lc1/b2;

    .line 49
    .line 50
    invoke-direct {p2, p3, p4}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v6, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move-object p3, p2

    .line 57
    :cond_3
    move-object v1, p3

    .line 58
    check-cast v1, Lc1/b2;

    .line 59
    .line 60
    new-instance v0, Le3/s;

    .line 61
    .line 62
    invoke-direct {v0, p0, p1}, Le3/s;-><init>(J)V

    .line 63
    .line 64
    .line 65
    shl-int/lit8 p0, p5, 0x6

    .line 66
    .line 67
    const p1, 0xe000

    .line 68
    .line 69
    .line 70
    and-int v7, p0, p1

    .line 71
    .line 72
    const/16 v8, 0x8

    .line 73
    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v5, 0x0

    .line 76
    invoke-static/range {v0 .. v8}, Lc1/e;->c(Ljava/lang/Object;Lc1/b2;Lc1/j;Ljava/lang/Float;Ljava/lang/String;Lay0/k;Ll2/o;II)Ll2/t2;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0
.end method
