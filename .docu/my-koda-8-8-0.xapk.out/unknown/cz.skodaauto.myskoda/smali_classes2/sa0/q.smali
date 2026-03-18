.class public final synthetic Lsa0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lsa0/s;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Lsa0/s;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lsa0/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsa0/q;->e:Lsa0/s;

    .line 4
    .line 5
    iput-boolean p2, p0, Lsa0/q;->f:Z

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lsa0/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/e;

    .line 7
    .line 8
    iget-object v1, p0, Lsa0/q;->e:Lsa0/s;

    .line 9
    .line 10
    iget-object v1, v1, Lsa0/s;->i:Lij0/a;

    .line 11
    .line 12
    const v2, 0x7f121573

    .line 13
    .line 14
    .line 15
    check-cast v1, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget-boolean p0, p0, Lsa0/q;->f:Z

    .line 22
    .line 23
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    new-instance v0, Llj0/e;

    .line 28
    .line 29
    iget-object v1, p0, Lsa0/q;->e:Lsa0/s;

    .line 30
    .line 31
    iget-object v1, v1, Lsa0/s;->i:Lij0/a;

    .line 32
    .line 33
    const v2, 0x7f12156b

    .line 34
    .line 35
    .line 36
    check-cast v1, Ljj0/f;

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    iget-boolean p0, p0, Lsa0/q;->f:Z

    .line 43
    .line 44
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
