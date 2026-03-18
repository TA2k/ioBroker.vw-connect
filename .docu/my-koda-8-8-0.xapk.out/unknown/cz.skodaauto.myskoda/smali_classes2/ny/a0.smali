.class public final synthetic Lny/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lmy/o;


# direct methods
.method public synthetic constructor <init>(Lmy/o;I)V
    .locals 0

    .line 1
    iput p2, p0, Lny/a0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lny/a0;->e:Lmy/o;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lny/a0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lny/a0;->e:Lmy/o;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lmy/o;->f:Ll2/v1;

    .line 9
    .line 10
    sget-object v0, Lmy/n;->e:Lmy/n;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ll2/v1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget-object p0, p0, Lmy/o;->f:Ll2/v1;

    .line 19
    .line 20
    sget-object v0, Lmy/n;->d:Lmy/n;

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ll2/v1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :pswitch_1
    iget-object p0, p0, Lmy/o;->f:Ll2/v1;

    .line 27
    .line 28
    sget-object v0, Lmy/n;->f:Lmy/n;

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ll2/v1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
