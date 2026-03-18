.class public abstract Lg1/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg1/e1;

.field public static final b:Lg1/e1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lg1/e1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x3

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v2, v3, v1}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lg1/f1;->a:Lg1/e1;

    .line 10
    .line 11
    new-instance v0, Lg1/e1;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v2, v3, v1}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lg1/f1;->b:Lg1/e1;

    .line 18
    .line 19
    return-void
.end method

.method public static a(Lx2/s;Lg1/i1;Lg1/w1;ZLi1/l;ZLg1/e1;Lay0/o;ZI)Lx2/s;
    .locals 9

    .line 1
    move/from16 v0, p9

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x4

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    const/4 p3, 0x1

    .line 8
    :cond_0
    move v3, p3

    .line 9
    and-int/lit8 p3, v0, 0x8

    .line 10
    .line 11
    if-eqz p3, :cond_1

    .line 12
    .line 13
    const/4 p4, 0x0

    .line 14
    :cond_1
    move-object v4, p4

    .line 15
    and-int/lit8 p3, v0, 0x10

    .line 16
    .line 17
    const/4 p4, 0x0

    .line 18
    if-eqz p3, :cond_2

    .line 19
    .line 20
    move v5, p4

    .line 21
    goto :goto_0

    .line 22
    :cond_2
    move v5, p5

    .line 23
    :goto_0
    and-int/lit8 p3, v0, 0x20

    .line 24
    .line 25
    if-eqz p3, :cond_3

    .line 26
    .line 27
    sget-object p3, Lg1/f1;->a:Lg1/e1;

    .line 28
    .line 29
    move-object v6, p3

    .line 30
    goto :goto_1

    .line 31
    :cond_3
    move-object v6, p6

    .line 32
    :goto_1
    and-int/lit16 p3, v0, 0x80

    .line 33
    .line 34
    if-eqz p3, :cond_4

    .line 35
    .line 36
    move v8, p4

    .line 37
    goto :goto_2

    .line 38
    :cond_4
    move/from16 v8, p8

    .line 39
    .line 40
    :goto_2
    new-instance v0, Landroidx/compose/foundation/gestures/DraggableElement;

    .line 41
    .line 42
    move-object v1, p1

    .line 43
    move-object v2, p2

    .line 44
    move-object/from16 v7, p7

    .line 45
    .line 46
    invoke-direct/range {v0 .. v8}, Landroidx/compose/foundation/gestures/DraggableElement;-><init>(Lg1/i1;Lg1/w1;ZLi1/l;ZLay0/o;Lay0/o;Z)V

    .line 47
    .line 48
    .line 49
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method

.method public static final b(Lay0/k;Ll2/o;)Lg1/i1;
    .locals 2

    .line 1
    invoke-static {p0, p1}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p1, Ll2/t;

    .line 6
    .line 7
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 12
    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    new-instance v0, La2/g;

    .line 16
    .line 17
    const/16 v1, 0x9

    .line 18
    .line 19
    invoke-direct {v0, p0, v1}, La2/g;-><init>(Ll2/b1;I)V

    .line 20
    .line 21
    .line 22
    new-instance p0, Lg1/b0;

    .line 23
    .line 24
    invoke-direct {p0, v0}, Lg1/b0;-><init>(La2/g;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    move-object v0, p0

    .line 31
    :cond_0
    check-cast v0, Lg1/i1;

    .line 32
    .line 33
    return-object v0
.end method
