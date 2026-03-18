.class public final Ly21/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lq41/b;


# direct methods
.method public synthetic constructor <init>(Ln7/b;Lq41/b;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly21/e;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Ly21/e;->b:Lq41/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    iget v0, p0, Ly21/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly21/e;->b:Lq41/b;

    .line 7
    .line 8
    check-cast p0, Lr31/i;

    .line 9
    .line 10
    sget-object v0, Lr31/d;->a:Lr31/d;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lr31/i;->d(Lr31/g;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object p0, p0, Ly21/e;->b:Lq41/b;

    .line 17
    .line 18
    check-cast p0, Lu31/h;

    .line 19
    .line 20
    sget-object v0, Lu31/d;->a:Lu31/d;

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lu31/h;->b(Lu31/e;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_1
    iget-object p0, p0, Ly21/e;->b:Lq41/b;

    .line 27
    .line 28
    check-cast p0, Lq31/h;

    .line 29
    .line 30
    sget-object v0, Lq31/d;->a:Lq31/d;

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lq31/h;->d(Lq31/f;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :pswitch_2
    iget-object p0, p0, Ly21/e;->b:Lq41/b;

    .line 37
    .line 38
    check-cast p0, Lt31/n;

    .line 39
    .line 40
    sget-object v0, Lt31/h;->a:Lt31/h;

    .line 41
    .line 42
    invoke-virtual {p0, v0}, Lt31/n;->f(Lt31/i;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
