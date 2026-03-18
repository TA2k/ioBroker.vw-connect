.class public final synthetic Ly70/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/e0;


# direct methods
.method public synthetic constructor <init>(Ly70/e0;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/p;->e:Ly70/e0;

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
    .locals 2

    .line 1
    iget v0, p0, Ly70/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/a;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/p;->e:Ly70/e0;

    .line 9
    .line 10
    iget-object p0, p0, Ly70/e0;->w:Lij0/a;

    .line 11
    .line 12
    const v1, 0x7f120371

    .line 13
    .line 14
    .line 15
    check-cast p0, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-object v0

    .line 25
    :pswitch_0
    new-instance v0, Llj0/b;

    .line 26
    .line 27
    iget-object p0, p0, Ly70/p;->e:Ly70/e0;

    .line 28
    .line 29
    iget-object p0, p0, Ly70/e0;->w:Lij0/a;

    .line 30
    .line 31
    const v1, 0x7f1211dc

    .line 32
    .line 33
    .line 34
    check-cast p0, Ljj0/f;

    .line 35
    .line 36
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const-string v1, "system://location_settings"

    .line 41
    .line 42
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    :pswitch_1
    new-instance v0, Llj0/a;

    .line 47
    .line 48
    iget-object p0, p0, Ly70/p;->e:Ly70/e0;

    .line 49
    .line 50
    iget-object p0, p0, Ly70/e0;->w:Lij0/a;

    .line 51
    .line 52
    const v1, 0x7f120379

    .line 53
    .line 54
    .line 55
    check-cast p0, Ljj0/f;

    .line 56
    .line 57
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
