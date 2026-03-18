.class public final synthetic Luz/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput p1, p0, Luz/z;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Luz/z;->e:Lay0/a;

    .line 4
    .line 5
    iput-object p3, p0, Luz/z;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Luz/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luz/z;->e:Lay0/a;

    .line 7
    .line 8
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    new-instance v0, Lq61/c;

    .line 12
    .line 13
    const/16 v1, 0xa

    .line 14
    .line 15
    iget-object p0, p0, Luz/z;->f:Ljava/lang/String;

    .line 16
    .line 17
    invoke-direct {v0, p0, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    iget-object v0, p0, Luz/z;->e:Lay0/a;

    .line 27
    .line 28
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    new-instance v0, Lq61/c;

    .line 32
    .line 33
    const/16 v1, 0x9

    .line 34
    .line 35
    iget-object p0, p0, Luz/z;->f:Ljava/lang/String;

    .line 36
    .line 37
    invoke-direct {v0, p0, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_1
    iget-object v0, p0, Luz/z;->e:Lay0/a;

    .line 47
    .line 48
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    new-instance v0, Lq61/c;

    .line 52
    .line 53
    const/16 v1, 0x8

    .line 54
    .line 55
    iget-object p0, p0, Luz/z;->f:Ljava/lang/String;

    .line 56
    .line 57
    invoke-direct {v0, p0, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 58
    .line 59
    .line 60
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 63
    .line 64
    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
