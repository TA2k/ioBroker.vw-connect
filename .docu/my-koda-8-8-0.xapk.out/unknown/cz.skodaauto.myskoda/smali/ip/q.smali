.class public final synthetic Lip/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lfv/i;


# direct methods
.method public synthetic constructor <init>(Lfv/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lip/q;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lip/q;->b:Lfv/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lip/q;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lip/q;->b:Lfv/i;

    .line 7
    .line 8
    invoke-virtual {p0}, Lfv/i;->a()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lip/q;->b:Lfv/i;

    .line 14
    .line 15
    invoke-virtual {p0}, Lfv/i;->a()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lip/q;->b:Lfv/i;

    .line 21
    .line 22
    invoke-virtual {p0}, Lfv/i;->a()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_2
    iget-object p0, p0, Lip/q;->b:Lfv/i;

    .line 28
    .line 29
    invoke-virtual {p0}, Lfv/i;->a()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
