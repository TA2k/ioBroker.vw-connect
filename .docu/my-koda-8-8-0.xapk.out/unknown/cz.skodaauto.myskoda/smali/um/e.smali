.class public final synthetic Lum/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lum/i;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lum/j;


# direct methods
.method public synthetic constructor <init>(Lum/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lum/e;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lum/e;->b:Lum/j;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget v0, p0, Lum/e;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lum/e;->b:Lum/j;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lum/j;->h()V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    invoke-virtual {p0}, Lum/j;->j()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
