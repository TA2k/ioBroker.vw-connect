.class public final synthetic Lnz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnz/j;


# direct methods
.method public synthetic constructor <init>(Lnz/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lnz/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnz/a;->e:Lnz/j;

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
    .locals 3

    .line 1
    iget v0, p0, Lnz/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/e;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/a;->e:Lnz/j;

    .line 9
    .line 10
    iget-object p0, p0, Lnz/j;->l:Lij0/a;

    .line 11
    .line 12
    const v1, 0x7f1200e0

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
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, v1}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_0
    new-instance v0, Llj0/e;

    .line 27
    .line 28
    iget-object p0, p0, Lnz/a;->e:Lnz/j;

    .line 29
    .line 30
    iget-object p0, p0, Lnz/j;->l:Lij0/a;

    .line 31
    .line 32
    const v1, 0x7f1200df

    .line 33
    .line 34
    .line 35
    check-cast p0, Ljj0/f;

    .line 36
    .line 37
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    const/4 v1, 0x1

    .line 42
    invoke-direct {v0, p0, v1}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    :pswitch_1
    iget-object p0, p0, Lnz/a;->e:Lnz/j;

    .line 47
    .line 48
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Lnz/e;

    .line 53
    .line 54
    iget-object v1, p0, Lnz/j;->l:Lij0/a;

    .line 55
    .line 56
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    check-cast v2, Lnz/e;

    .line 61
    .line 62
    iget-boolean v2, v2, Lnz/e;->g:Z

    .line 63
    .line 64
    invoke-static {v0, v1, v2}, Ljp/db;->g(Lnz/e;Lij0/a;Z)Lnz/e;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 69
    .line 70
    .line 71
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0

    .line 74
    :pswitch_2
    new-instance v0, Llj0/a;

    .line 75
    .line 76
    iget-object p0, p0, Lnz/a;->e:Lnz/j;

    .line 77
    .line 78
    iget-object p0, p0, Lnz/j;->l:Lij0/a;

    .line 79
    .line 80
    const v1, 0x7f1200e8

    .line 81
    .line 82
    .line 83
    check-cast p0, Ljj0/f;

    .line 84
    .line 85
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    return-object v0

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
