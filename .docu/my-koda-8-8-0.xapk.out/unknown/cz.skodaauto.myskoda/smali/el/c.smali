.class public final synthetic Lel/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lay0/a;

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IIILay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lel/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p5, p0, Lel/c;->i:Ljava/lang/Object;

    iput-object p6, p0, Lel/c;->j:Ljava/lang/Object;

    iput-object p7, p0, Lel/c;->k:Ljava/lang/Object;

    iput p1, p0, Lel/c;->e:I

    iput-object p4, p0, Lel/c;->f:Lay0/a;

    iput p2, p0, Lel/c;->g:I

    iput p3, p0, Lel/c;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lhp0/e;ILt3/k;Lay0/a;II)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lel/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lel/c;->i:Ljava/lang/Object;

    iput-object p2, p0, Lel/c;->j:Ljava/lang/Object;

    iput p3, p0, Lel/c;->e:I

    iput-object p4, p0, Lel/c;->k:Ljava/lang/Object;

    iput-object p5, p0, Lel/c;->f:Lay0/a;

    iput p6, p0, Lel/c;->g:I

    iput p7, p0, Lel/c;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lel/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lel/c;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lx2/s;

    .line 10
    .line 11
    iget-object v0, p0, Lel/c;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Lhp0/e;

    .line 15
    .line 16
    iget-object v0, p0, Lel/c;->k:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v4, v0

    .line 19
    check-cast v4, Lt3/k;

    .line 20
    .line 21
    move-object v6, p1

    .line 22
    check-cast v6, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget p1, p0, Lel/c;->g:I

    .line 30
    .line 31
    or-int/lit8 p1, p1, 0x1

    .line 32
    .line 33
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    iget v3, p0, Lel/c;->e:I

    .line 38
    .line 39
    iget-object v5, p0, Lel/c;->f:Lay0/a;

    .line 40
    .line 41
    iget v8, p0, Lel/c;->h:I

    .line 42
    .line 43
    invoke-static/range {v1 .. v8}, Llp/xa;->c(Lx2/s;Lhp0/e;ILt3/k;Lay0/a;Ll2/o;II)V

    .line 44
    .line 45
    .line 46
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_0
    iget-object v0, p0, Lel/c;->i:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v1, v0

    .line 52
    check-cast v1, Ljava/lang/String;

    .line 53
    .line 54
    iget-object v0, p0, Lel/c;->j:Ljava/lang/Object;

    .line 55
    .line 56
    move-object v2, v0

    .line 57
    check-cast v2, Ljava/lang/String;

    .line 58
    .line 59
    iget-object v0, p0, Lel/c;->k:Ljava/lang/Object;

    .line 60
    .line 61
    move-object v3, v0

    .line 62
    check-cast v3, Ljava/lang/String;

    .line 63
    .line 64
    move-object v6, p1

    .line 65
    check-cast v6, Ll2/o;

    .line 66
    .line 67
    check-cast p2, Ljava/lang/Integer;

    .line 68
    .line 69
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget p1, p0, Lel/c;->g:I

    .line 73
    .line 74
    or-int/lit8 p1, p1, 0x1

    .line 75
    .line 76
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    iget v4, p0, Lel/c;->e:I

    .line 81
    .line 82
    iget-object v5, p0, Lel/c;->f:Lay0/a;

    .line 83
    .line 84
    iget v8, p0, Lel/c;->h:I

    .line 85
    .line 86
    invoke-static/range {v1 .. v8}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
