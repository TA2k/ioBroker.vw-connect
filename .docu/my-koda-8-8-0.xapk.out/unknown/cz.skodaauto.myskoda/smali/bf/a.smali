.class public final synthetic Lbf/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbf/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbf/a;->e:Lay0/a;

    .line 4
    .line 5
    iput-object p2, p0, Lbf/a;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lbf/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Lbf/a;->e:Lay0/a;

    .line 15
    .line 16
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    iget-object p0, p0, Lbf/a;->f:Lay0/a;

    .line 21
    .line 22
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    check-cast p1, Lw1/g;

    .line 29
    .line 30
    iget-object v0, p0, Lbf/a;->e:Lay0/a;

    .line 31
    .line 32
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lbf/a;->f:Lay0/a;

    .line 36
    .line 37
    if-eqz p0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Ljava/lang/Boolean;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    const/4 p0, 0x1

    .line 51
    :goto_1
    if-eqz p0, :cond_2

    .line 52
    .line 53
    invoke-interface {p1}, Lw1/g;->close()V

    .line 54
    .line 55
    .line 56
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_1
    check-cast p1, Lhi/a;

    .line 60
    .line 61
    const-string v0, "$this$sdkViewModel"

    .line 62
    .line 63
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    new-instance p1, Lbf/d;

    .line 67
    .line 68
    iget-object v0, p0, Lbf/a;->e:Lay0/a;

    .line 69
    .line 70
    iget-object p0, p0, Lbf/a;->f:Lay0/a;

    .line 71
    .line 72
    invoke-direct {p1, v0, p0}, Lbf/d;-><init>(Lay0/a;Lay0/a;)V

    .line 73
    .line 74
    .line 75
    return-object p1

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
