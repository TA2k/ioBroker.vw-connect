.class public final synthetic Lg0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lb0/n1;


# direct methods
.method public synthetic constructor <init>(Lb0/n1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg0/d;->e:Lb0/n1;

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
    iget v0, p0, Lg0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg0/d;->e:Lb0/n1;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Lb0/n1;->r()V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Lg0/d;->e:Lb0/n1;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lb0/n1;->r()V

    .line 19
    .line 20
    .line 21
    :cond_1
    return-void

    .line 22
    :pswitch_1
    iget-object p0, p0, Lg0/d;->e:Lb0/n1;

    .line 23
    .line 24
    invoke-virtual {p0}, Lb0/n1;->r()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
