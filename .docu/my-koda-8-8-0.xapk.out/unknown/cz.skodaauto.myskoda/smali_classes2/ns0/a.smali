.class public final synthetic Lns0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lns0/f;


# direct methods
.method public synthetic constructor <init>(Lns0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lns0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lns0/a;->e:Lns0/f;

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
    iget v0, p0, Lns0/a;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lns0/a;->e:Lns0/f;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-boolean p0, p0, Lns0/f;->u:Z

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    sget-object p0, Lvg0/a;->e:Lvg0/a;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    sget-object p0, Lvg0/a;->c:Lvg0/a;

    .line 16
    .line 17
    :goto_0
    return-object p0

    .line 18
    :pswitch_0
    iget-boolean p0, p0, Lns0/f;->u:Z

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    sget-object p0, Lvg0/a;->d:Lvg0/a;

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    sget-object p0, Lvg0/a;->b:Lvg0/a;

    .line 26
    .line 27
    :goto_1
    return-object p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
