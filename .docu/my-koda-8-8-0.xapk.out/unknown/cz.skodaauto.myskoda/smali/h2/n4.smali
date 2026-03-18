.class public final synthetic Lh2/n4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lf2/u;


# direct methods
.method public synthetic constructor <init>(Lf2/u;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/n4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/n4;->e:Lf2/u;

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
    .locals 7

    .line 1
    iget v0, p0, Lh2/n4;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lh2/n4;->e:Lf2/u;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lh2/w7;->a:Ll2/e0;

    .line 9
    .line 10
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/v7;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lh2/v7;->b:Lg2/b;

    .line 19
    .line 20
    if-nez p0, :cond_1

    .line 21
    .line 22
    :cond_0
    sget-object p0, Lh2/r;->c:Lg2/b;

    .line 23
    .line 24
    :cond_1
    return-object p0

    .line 25
    :pswitch_0
    sget-object v0, Lh2/w7;->a:Ll2/e0;

    .line 26
    .line 27
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lh2/v7;

    .line 32
    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    iget-object v0, p0, Lf2/u;->y:Lg2/a;

    .line 36
    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    invoke-virtual {p0, v0}, Lv3/n;->Y0(Lv3/m;)V

    .line 40
    .line 41
    .line 42
    :cond_2
    const/4 v0, 0x0

    .line 43
    iput-object v0, p0, Lf2/u;->y:Lg2/a;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_3
    iget-object v0, p0, Lf2/u;->y:Lg2/a;

    .line 47
    .line 48
    if-nez v0, :cond_4

    .line 49
    .line 50
    new-instance v5, Lf2/t;

    .line 51
    .line 52
    const/4 v0, 0x2

    .line 53
    invoke-direct {v5, p0, v0}, Lf2/t;-><init>(Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    new-instance v6, Lh2/n4;

    .line 57
    .line 58
    const/4 v0, 0x1

    .line 59
    invoke-direct {v6, p0, v0}, Lh2/n4;-><init>(Lf2/u;I)V

    .line 60
    .line 61
    .line 62
    iget-object v2, p0, Lf2/u;->u:Li1/l;

    .line 63
    .line 64
    iget-boolean v3, p0, Lf2/u;->v:Z

    .line 65
    .line 66
    iget v4, p0, Lf2/u;->w:F

    .line 67
    .line 68
    sget-object v0, Lg2/f;->a:Lc1/a2;

    .line 69
    .line 70
    new-instance v1, Lg2/a;

    .line 71
    .line 72
    invoke-direct/range {v1 .. v6}, Lg2/a;-><init>(Li1/l;ZFLe3/t;Lay0/a;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, v1}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 76
    .line 77
    .line 78
    iput-object v1, p0, Lf2/u;->y:Lg2/a;

    .line 79
    .line 80
    :cond_4
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
