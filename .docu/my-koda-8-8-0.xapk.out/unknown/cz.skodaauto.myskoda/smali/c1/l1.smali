.class public final synthetic Lc1/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    iput p1, p0, Lc1/l1;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lc1/l1;->e:Lay0/n;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lc1/l1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lc6/b;

    .line 7
    .line 8
    iget-object v0, p1, Lc6/b;->a:Ljava/lang/Object;

    .line 9
    .line 10
    const-string v1, "first"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    check-cast v0, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    invoke-static {v0, v1}, Lzo/e;->b(J)Ljava/time/LocalDate;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object p1, p1, Lc6/b;->b:Ljava/lang/Object;

    .line 26
    .line 27
    const-string v1, "second"

    .line 28
    .line 29
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    check-cast p1, Ljava/lang/Number;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    invoke-static {v1, v2}, Lzo/e;->b(J)Ljava/time/LocalDate;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iget-object p0, p0, Lc1/l1;->e:Lay0/n;

    .line 43
    .line 44
    invoke-interface {p0, v0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    sget-object v0, Lc1/d;->j:Lc1/b2;

    .line 51
    .line 52
    check-cast p1, Lc1/i;

    .line 53
    .line 54
    iget-object v1, p1, Lc1/i;->e:Ll2/j1;

    .line 55
    .line 56
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iget-object v0, v0, Lc1/b2;->b:Lay0/k;

    .line 61
    .line 62
    iget-object p1, p1, Lc1/i;->f:Lc1/p;

    .line 63
    .line 64
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    iget-object p0, p0, Lc1/l1;->e:Lay0/n;

    .line 69
    .line 70
    invoke-interface {p0, v1, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
