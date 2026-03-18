.class public final Lt1/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final b:Lt1/c;

.field public static final c:Lt1/c;

.field public static final d:Ldj/a;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt1/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lt1/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lt1/c;->b:Lt1/c;

    .line 8
    .line 9
    new-instance v0, Lt1/c;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lt1/c;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lt1/c;->c:Lt1/c;

    .line 16
    .line 17
    new-instance v0, Ldj/a;

    .line 18
    .line 19
    const/16 v1, 0xe

    .line 20
    .line 21
    invoke-direct {v0, v1}, Ldj/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lt1/c;->d:Ldj/a;

    .line 25
    .line 26
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lt1/c;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 3

    .line 1
    iget p0, p0, Lt1/c;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    sget-object p3, Lt1/c;->d:Ldj/a;

    .line 15
    .line 16
    sget-object p4, Lmx0/t;->d:Lmx0/t;

    .line 17
    .line 18
    invoke-interface {p1, p0, p2, p4, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    new-instance p0, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 30
    .line 31
    .line 32
    move-object v0, p2

    .line 33
    check-cast v0, Ljava/util/Collection;

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    const/4 v1, 0x0

    .line 40
    :goto_0
    if-ge v1, v0, :cond_0

    .line 41
    .line 42
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    check-cast v2, Lt3/p0;

    .line 47
    .line 48
    invoke-interface {v2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    add-int/lit8 v1, v1, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 63
    .line 64
    .line 65
    move-result p3

    .line 66
    new-instance p4, Le2/j0;

    .line 67
    .line 68
    const/4 v0, 0x2

    .line 69
    invoke-direct {p4, p0, v0}, Le2/j0;-><init>(Ljava/util/ArrayList;I)V

    .line 70
    .line 71
    .line 72
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 73
    .line 74
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
