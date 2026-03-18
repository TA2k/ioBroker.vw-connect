.class public final synthetic Lrk/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lqg/j;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lqg/j;I)V
    .locals 0

    .line 1
    iput p3, p0, Lrk/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrk/c;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lrk/c;->f:Lqg/j;

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
    iget v0, p0, Lrk/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lqg/e;

    .line 7
    .line 8
    iget-object v1, p0, Lrk/c;->f:Lqg/j;

    .line 9
    .line 10
    iget-object v1, v1, Lqg/j;->a:Ljava/lang/String;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lqg/e;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lrk/c;->e:Lay0/k;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    new-instance v0, Lqg/e;

    .line 24
    .line 25
    iget-object v1, p0, Lrk/c;->f:Lqg/j;

    .line 26
    .line 27
    iget-object v1, v1, Lqg/j;->a:Ljava/lang/String;

    .line 28
    .line 29
    invoke-direct {v0, v1}, Lqg/e;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lrk/c;->e:Lay0/k;

    .line 33
    .line 34
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
