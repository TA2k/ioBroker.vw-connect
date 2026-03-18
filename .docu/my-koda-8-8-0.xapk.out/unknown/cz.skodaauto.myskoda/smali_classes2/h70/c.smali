.class public final Lh70/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lpx0/i;


# direct methods
.method public synthetic constructor <init>(Lpx0/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh70/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh70/c;->e:Lpx0/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 0

    .line 1
    iget p2, p0, Lh70/c;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh70/c;->e:Lpx0/i;

    .line 7
    .line 8
    sget-object p2, Lx41/u;->e:Lx41/u;

    .line 9
    .line 10
    invoke-virtual {p0, p2}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    iget-object p0, p0, Lh70/c;->e:Lpx0/i;

    .line 18
    .line 19
    sget-object p2, Lx41/u;->d:Lx41/u;

    .line 20
    .line 21
    invoke-virtual {p0, p2}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V

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
