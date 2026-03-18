.class public final synthetic Lhu/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lhu/a0;


# direct methods
.method public synthetic constructor <init>(Lhu/a0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhu/z;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhu/z;->e:Lhu/a0;

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
    iget v0, p0, Lhu/z;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lhu/z;->e:Lhu/a0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lhu/a0;->a:Landroid/content/Context;

    .line 9
    .line 10
    invoke-static {p0}, Lhu/r;->b(Landroid/content/Context;)Lhu/b0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lhu/a0;->e:Llx0/q;

    .line 16
    .line 17
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Lhu/b0;

    .line 22
    .line 23
    iget-object p0, p0, Lhu/b0;->a:Ljava/lang/String;

    .line 24
    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
