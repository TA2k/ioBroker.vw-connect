.class public final Lc1/y1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lc1/w1;


# direct methods
.method public synthetic constructor <init>(Lc1/w1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc1/y1;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lc1/y1;->b:Lc1/w1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final dispose()V
    .locals 1

    .line 1
    iget v0, p0, Lc1/y1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc1/y1;->b:Lc1/w1;

    .line 7
    .line 8
    invoke-virtual {p0}, Lc1/w1;->i()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lc1/w1;->a:Lap0/o;

    .line 12
    .line 13
    invoke-virtual {p0}, Lap0/o;->W()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    iget-object p0, p0, Lc1/y1;->b:Lc1/w1;

    .line 18
    .line 19
    invoke-virtual {p0}, Lc1/w1;->i()V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lc1/w1;->a:Lap0/o;

    .line 23
    .line 24
    invoke-virtual {p0}, Lap0/o;->W()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
