.class public final synthetic Lyg0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lql0/g;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lql0/g;I)V
    .locals 0

    .line 1
    iput p3, p0, Lyg0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyg0/b;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lyg0/b;->f:Lql0/g;

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
    .locals 1

    .line 1
    iget v0, p0, Lyg0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lyg0/b;->f:Lql0/g;

    .line 7
    .line 8
    iget-object v0, v0, Lql0/g;->a:Lql0/f;

    .line 9
    .line 10
    iget-object p0, p0, Lyg0/b;->e:Lay0/k;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object v0, p0, Lyg0/b;->e:Lay0/k;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lyg0/b;->f:Lql0/g;

    .line 23
    .line 24
    iget-object p0, p0, Lql0/g;->a:Lql0/f;

    .line 25
    .line 26
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-object v0, p0, Lyg0/b;->f:Lql0/g;

    .line 33
    .line 34
    iget-object v0, v0, Lql0/g;->a:Lql0/f;

    .line 35
    .line 36
    iget-object p0, p0, Lyg0/b;->e:Lay0/k;

    .line 37
    .line 38
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :pswitch_2
    iget-object v0, p0, Lyg0/b;->f:Lql0/g;

    .line 43
    .line 44
    iget-object v0, v0, Lql0/g;->a:Lql0/f;

    .line 45
    .line 46
    iget-object p0, p0, Lyg0/b;->e:Lay0/k;

    .line 47
    .line 48
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
