.class public final synthetic Leu/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljs/b;

.field public final synthetic f:Lgu/d;


# direct methods
.method public synthetic constructor <init>(Ljs/b;Lgu/d;I)V
    .locals 0

    .line 1
    iput p3, p0, Leu/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Leu/a;->e:Ljs/b;

    .line 4
    .line 5
    iput-object p2, p0, Leu/a;->f:Lgu/d;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget v0, p0, Leu/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Leu/a;->e:Ljs/b;

    .line 7
    .line 8
    iget-object p0, p0, Leu/a;->f:Lgu/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljs/b;->a(Lgu/d;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Leu/a;->e:Ljs/b;

    .line 15
    .line 16
    iget-object p0, p0, Leu/a;->f:Lgu/d;

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Ljs/b;->a(Lgu/d;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
