.class public final synthetic Lm60/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll60/c;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ll60/c;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;III)V
    .locals 0

    .line 1
    iput p10, p0, Lm60/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm60/b;->e:Ll60/c;

    .line 4
    .line 5
    iput-object p2, p0, Lm60/b;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Lm60/b;->g:Lay0/k;

    .line 8
    .line 9
    iput-object p4, p0, Lm60/b;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lm60/b;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Lm60/b;->j:Lay0/a;

    .line 14
    .line 15
    iput-object p7, p0, Lm60/b;->k:Lay0/a;

    .line 16
    .line 17
    iput p9, p0, Lm60/b;->l:I

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lm60/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v8, p1

    .line 7
    check-cast v8, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v9

    .line 19
    iget-object v1, p0, Lm60/b;->e:Ll60/c;

    .line 20
    .line 21
    iget-object v2, p0, Lm60/b;->f:Lay0/a;

    .line 22
    .line 23
    iget-object v3, p0, Lm60/b;->g:Lay0/k;

    .line 24
    .line 25
    iget-object v4, p0, Lm60/b;->h:Lay0/a;

    .line 26
    .line 27
    iget-object v5, p0, Lm60/b;->i:Lay0/a;

    .line 28
    .line 29
    iget-object v6, p0, Lm60/b;->j:Lay0/a;

    .line 30
    .line 31
    iget-object v7, p0, Lm60/b;->k:Lay0/a;

    .line 32
    .line 33
    iget v10, p0, Lm60/b;->l:I

    .line 34
    .line 35
    invoke-static/range {v1 .. v10}, Lm60/a;->e(Ll60/c;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 36
    .line 37
    .line 38
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    move-object v7, p1

    .line 42
    check-cast v7, Ll2/o;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const/4 p1, 0x1

    .line 50
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result v8

    .line 54
    iget-object v0, p0, Lm60/b;->e:Ll60/c;

    .line 55
    .line 56
    iget-object v1, p0, Lm60/b;->f:Lay0/a;

    .line 57
    .line 58
    iget-object v2, p0, Lm60/b;->g:Lay0/k;

    .line 59
    .line 60
    iget-object v3, p0, Lm60/b;->h:Lay0/a;

    .line 61
    .line 62
    iget-object v4, p0, Lm60/b;->i:Lay0/a;

    .line 63
    .line 64
    iget-object v5, p0, Lm60/b;->j:Lay0/a;

    .line 65
    .line 66
    iget-object v6, p0, Lm60/b;->k:Lay0/a;

    .line 67
    .line 68
    iget v9, p0, Lm60/b;->l:I

    .line 69
    .line 70
    invoke-static/range {v0 .. v9}, Lm60/a;->e(Ll60/c;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_1
    move-object v7, p1

    .line 75
    check-cast v7, Ll2/o;

    .line 76
    .line 77
    check-cast p2, Ljava/lang/Integer;

    .line 78
    .line 79
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    const/4 p1, 0x1

    .line 83
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 84
    .line 85
    .line 86
    move-result v8

    .line 87
    iget-object v0, p0, Lm60/b;->e:Ll60/c;

    .line 88
    .line 89
    iget-object v1, p0, Lm60/b;->f:Lay0/a;

    .line 90
    .line 91
    iget-object v2, p0, Lm60/b;->g:Lay0/k;

    .line 92
    .line 93
    iget-object v3, p0, Lm60/b;->h:Lay0/a;

    .line 94
    .line 95
    iget-object v4, p0, Lm60/b;->i:Lay0/a;

    .line 96
    .line 97
    iget-object v5, p0, Lm60/b;->j:Lay0/a;

    .line 98
    .line 99
    iget-object v6, p0, Lm60/b;->k:Lay0/a;

    .line 100
    .line 101
    iget v9, p0, Lm60/b;->l:I

    .line 102
    .line 103
    invoke-static/range {v0 .. v9}, Lm60/a;->e(Ll60/c;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
