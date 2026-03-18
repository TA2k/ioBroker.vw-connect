.class public final Lw40/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw40/h;


# direct methods
.method public synthetic constructor <init>(Lw40/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw40/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw40/e;->e:Lw40/h;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget p2, p0, Lw40/e;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lon0/r;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lw40/e;->e:Lw40/h;

    .line 11
    .line 12
    iget-object p0, p0, Lw40/h;->i:Lnn0/v;

    .line 13
    .line 14
    const/4 p2, 0x0

    .line 15
    const/16 v0, 0xff

    .line 16
    .line 17
    invoke-static {p1, p2, v0}, Lon0/r;->a(Lon0/r;Ljava/lang/String;I)Lon0/r;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, p1}, Lnn0/v;->a(Lon0/r;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_0
    check-cast p1, Lon0/r;

    .line 28
    .line 29
    if-eqz p1, :cond_2

    .line 30
    .line 31
    iget-object p1, p1, Lon0/r;->f:Lon0/s;

    .line 32
    .line 33
    if-eqz p1, :cond_2

    .line 34
    .line 35
    iget-object p1, p1, Lon0/s;->b:Lon0/a;

    .line 36
    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    iget-object p0, p0, Lw40/e;->e:Lw40/h;

    .line 40
    .line 41
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    check-cast p2, Lw40/g;

    .line 46
    .line 47
    iget-object v0, p1, Lon0/a;->a:Ljava/lang/String;

    .line 48
    .line 49
    iget-object p1, p1, Lon0/a;->b:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    const/16 v2, 0x50

    .line 56
    .line 57
    if-ge v1, v2, :cond_1

    .line 58
    .line 59
    const/4 v1, 0x1

    .line 60
    goto :goto_0

    .line 61
    :cond_1
    const/4 v1, 0x0

    .line 62
    :goto_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    const-string p2, "subtitle"

    .line 66
    .line 67
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    new-instance p2, Lw40/g;

    .line 71
    .line 72
    invoke-direct {p2, v0, p1, v1}, Lw40/g;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
