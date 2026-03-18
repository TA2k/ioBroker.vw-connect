.class public final synthetic Lcl/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc3/j;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lc3/j;I)V
    .locals 0

    .line 1
    iput p3, p0, Lcl/c;->d:I

    iput-object p1, p0, Lcl/c;->f:Lay0/a;

    iput-object p2, p0, Lcl/c;->e:Lc3/j;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lc3/j;Lay0/a;I)V
    .locals 0

    .line 2
    iput p3, p0, Lcl/c;->d:I

    iput-object p1, p0, Lcl/c;->e:Lc3/j;

    iput-object p2, p0, Lcl/c;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lcl/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcl/c;->f:Lay0/a;

    .line 7
    .line 8
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lcl/c;->e:Lc3/j;

    .line 12
    .line 13
    invoke-static {p0}, Lc3/j;->a(Lc3/j;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object v0, p0, Lcl/c;->f:Lay0/a;

    .line 20
    .line 21
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lcl/c;->e:Lc3/j;

    .line 25
    .line 26
    invoke-static {p0}, Lc3/j;->a(Lc3/j;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :pswitch_1
    iget-object v0, p0, Lcl/c;->e:Lc3/j;

    .line 31
    .line 32
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lcl/c;->f:Lay0/a;

    .line 36
    .line 37
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :pswitch_2
    iget-object v0, p0, Lcl/c;->e:Lc3/j;

    .line 42
    .line 43
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lcl/c;->f:Lay0/a;

    .line 47
    .line 48
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_3
    iget-object v0, p0, Lcl/c;->e:Lc3/j;

    .line 53
    .line 54
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lcl/c;->f:Lay0/a;

    .line 58
    .line 59
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_4
    iget-object v0, p0, Lcl/c;->e:Lc3/j;

    .line 64
    .line 65
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lcl/c;->f:Lay0/a;

    .line 69
    .line 70
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
