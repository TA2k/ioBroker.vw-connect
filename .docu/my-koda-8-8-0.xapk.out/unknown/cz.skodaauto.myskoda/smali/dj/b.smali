.class public final synthetic Ldj/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ldj/g;


# direct methods
.method public synthetic constructor <init>(Ldj/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Ldj/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldj/b;->e:Ldj/g;

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
    .locals 4

    .line 1
    iget v0, p0, Ldj/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ldj/b;->e:Ldj/g;

    .line 7
    .line 8
    iget-object v0, p0, Ldj/g;->g:Lyy0/c2;

    .line 9
    .line 10
    new-instance v1, La90/c;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    const/16 v3, 0x15

    .line 14
    .line 15
    invoke-direct {v1, v2, p0, v3}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iget-object p0, p0, Ldj/g;->b:Lvy0/b0;

    .line 27
    .line 28
    new-instance v1, Lxi/c;

    .line 29
    .line 30
    sget-object v2, Lyy0/u1;->b:Lyy0/w1;

    .line 31
    .line 32
    const-string v3, "LegalData"

    .line 33
    .line 34
    invoke-direct {v1, v2, v3}, Lxi/c;-><init>(Lyy0/v1;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    sget-object v2, Lri/b;->a:Lri/b;

    .line 38
    .line 39
    invoke-static {v0, p0, v1, v2}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_0
    iget-object p0, p0, Ldj/b;->e:Ldj/g;

    .line 45
    .line 46
    iget-object v0, p0, Ldj/g;->c:Llx0/q;

    .line 47
    .line 48
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Lyy0/a2;

    .line 53
    .line 54
    new-instance v1, La50/h;

    .line 55
    .line 56
    const/16 v2, 0x11

    .line 57
    .line 58
    invoke-direct {v1, v0, v2}, La50/h;-><init>(Lyy0/i;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    iget-object p0, p0, Ldj/g;->b:Lvy0/b0;

    .line 66
    .line 67
    new-instance v1, Lxi/c;

    .line 68
    .line 69
    sget-object v2, Lyy0/u1;->b:Lyy0/w1;

    .line 70
    .line 71
    const-string v3, "LegalDocuments"

    .line 72
    .line 73
    invoke-direct {v1, v2, v3}, Lxi/c;-><init>(Lyy0/v1;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    sget-object v2, Lri/b;->a:Lri/b;

    .line 77
    .line 78
    invoke-static {v0, p0, v1, v2}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
