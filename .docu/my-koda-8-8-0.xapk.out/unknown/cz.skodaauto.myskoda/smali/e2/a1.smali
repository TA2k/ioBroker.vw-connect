.class public final synthetic Le2/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le2/w0;


# direct methods
.method public synthetic constructor <init>(Le2/w0;I)V
    .locals 0

    .line 1
    iput p2, p0, Le2/a1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/a1;->e:Le2/w0;

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
    .locals 5

    .line 1
    iget v0, p0, Le2/a1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le2/a1;->e:Le2/w0;

    .line 7
    .line 8
    iget-object p0, p0, Le2/w0;->f:Lay0/a;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object p0, p0, Le2/a1;->e:Le2/w0;

    .line 19
    .line 20
    invoke-virtual {p0}, Le2/w0;->m()Ll4/v;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v0, v0, Ll4/v;->a:Lg4/g;

    .line 25
    .line 26
    invoke-virtual {p0}, Le2/w0;->m()Ll4/v;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object v1, v1, Ll4/v;->a:Lg4/g;

    .line 31
    .line 32
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/4 v2, 0x0

    .line 39
    invoke-static {v2, v1}, Lg4/f0;->b(II)J

    .line 40
    .line 41
    .line 42
    move-result-wide v1

    .line 43
    invoke-static {v0, v1, v2}, Le2/w0;->e(Lg4/g;J)Ll4/v;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-object v1, p0, Le2/w0;->c:Lay0/k;

    .line 48
    .line 49
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    iget-wide v0, v0, Ll4/v;->b:J

    .line 53
    .line 54
    new-instance v2, Lg4/o0;

    .line 55
    .line 56
    invoke-direct {v2, v0, v1}, Lg4/o0;-><init>(J)V

    .line 57
    .line 58
    .line 59
    iput-object v2, p0, Le2/w0;->v:Lg4/o0;

    .line 60
    .line 61
    iget-object v2, p0, Le2/w0;->t:Ll4/v;

    .line 62
    .line 63
    const/4 v3, 0x0

    .line 64
    const/4 v4, 0x5

    .line 65
    invoke-static {v2, v3, v0, v1, v4}, Ll4/v;->a(Ll4/v;Lg4/g;JI)Ll4/v;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iput-object v0, p0, Le2/w0;->t:Ll4/v;

    .line 70
    .line 71
    const/4 v0, 0x1

    .line 72
    invoke-virtual {p0, v0}, Le2/w0;->h(Z)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_1
    iget-object p0, p0, Le2/a1;->e:Le2/w0;

    .line 79
    .line 80
    iget-boolean p0, p0, Le2/w0;->A:Z

    .line 81
    .line 82
    xor-int/lit8 p0, p0, 0x1

    .line 83
    .line 84
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
