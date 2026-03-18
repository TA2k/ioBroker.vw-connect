.class public final Lk1/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final b:Lk1/m;

.field public static final c:Lk1/m;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lk1/m;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lk1/m;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lk1/m;->b:Lk1/m;

    .line 8
    .line 9
    new-instance v0, Lk1/m;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lk1/m;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lk1/m;->c:Lk1/m;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lk1/m;->a:I

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
    .locals 1

    .line 1
    iget p0, p0, Lk1/m;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p3, p4}, Lt4/a;->f(J)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 p2, 0x0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move p0, p2

    .line 19
    :goto_0
    invoke-static {p3, p4}, Lt4/a;->e(J)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    :cond_1
    new-instance p3, Ldj/a;

    .line 30
    .line 31
    const/16 p4, 0xe

    .line 32
    .line 33
    invoke-direct {p3, p4}, Ldj/a;-><init>(I)V

    .line 34
    .line 35
    .line 36
    sget-object p4, Lmx0/t;->d:Lmx0/t;

    .line 37
    .line 38
    invoke-interface {p1, p0, p2, p4, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_0
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    new-instance p3, Ldj/a;

    .line 52
    .line 53
    const/16 p4, 0xe

    .line 54
    .line 55
    invoke-direct {p3, p4}, Ldj/a;-><init>(I)V

    .line 56
    .line 57
    .line 58
    sget-object p4, Lmx0/t;->d:Lmx0/t;

    .line 59
    .line 60
    invoke-interface {p1, p0, p2, p4, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
