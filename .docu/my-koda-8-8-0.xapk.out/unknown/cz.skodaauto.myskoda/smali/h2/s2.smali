.class public final synthetic Lh2/s2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;ZZLay0/a;ZLjava/lang/String;Lh2/z1;I)V
    .locals 0

    .line 1
    const/4 p9, 0x0

    iput p9, p0, Lh2/s2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/s2;->j:Ljava/lang/Object;

    iput-object p2, p0, Lh2/s2;->e:Lx2/s;

    iput-boolean p3, p0, Lh2/s2;->f:Z

    iput-boolean p4, p0, Lh2/s2;->g:Z

    iput-object p5, p0, Lh2/s2;->i:Lay0/a;

    iput-boolean p6, p0, Lh2/s2;->h:Z

    iput-object p7, p0, Lh2/s2;->k:Ljava/lang/Object;

    iput-object p8, p0, Lh2/s2;->l:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p9, 0x1

    iput p9, p0, Lh2/s2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/s2;->e:Lx2/s;

    iput-boolean p2, p0, Lh2/s2;->f:Z

    iput-boolean p3, p0, Lh2/s2;->g:Z

    iput-boolean p4, p0, Lh2/s2;->h:Z

    iput-object p5, p0, Lh2/s2;->i:Lay0/a;

    iput-object p6, p0, Lh2/s2;->j:Ljava/lang/Object;

    iput-object p7, p0, Lh2/s2;->k:Ljava/lang/Object;

    iput-object p8, p0, Lh2/s2;->l:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lh2/s2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/s2;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v6, v0

    .line 9
    check-cast v6, Lay0/a;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/s2;->k:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v7, v0

    .line 14
    check-cast v7, Lay0/a;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/s2;->l:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v8, v0

    .line 19
    check-cast v8, Lay0/a;

    .line 20
    .line 21
    move-object v9, p1

    .line 22
    check-cast v9, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const/4 p1, 0x1

    .line 30
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 31
    .line 32
    .line 33
    move-result v10

    .line 34
    iget-object v1, p0, Lh2/s2;->e:Lx2/s;

    .line 35
    .line 36
    iget-boolean v2, p0, Lh2/s2;->f:Z

    .line 37
    .line 38
    iget-boolean v3, p0, Lh2/s2;->g:Z

    .line 39
    .line 40
    iget-boolean v4, p0, Lh2/s2;->h:Z

    .line 41
    .line 42
    iget-object v5, p0, Lh2/s2;->i:Lay0/a;

    .line 43
    .line 44
    invoke-static/range {v1 .. v10}, Lz61/m;->e(Lx2/s;ZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    iget-object v0, p0, Lh2/s2;->j:Ljava/lang/Object;

    .line 51
    .line 52
    move-object v1, v0

    .line 53
    check-cast v1, Ljava/lang/String;

    .line 54
    .line 55
    iget-object v0, p0, Lh2/s2;->k:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v7, v0

    .line 58
    check-cast v7, Ljava/lang/String;

    .line 59
    .line 60
    iget-object v0, p0, Lh2/s2;->l:Ljava/lang/Object;

    .line 61
    .line 62
    move-object v8, v0

    .line 63
    check-cast v8, Lh2/z1;

    .line 64
    .line 65
    move-object v9, p1

    .line 66
    check-cast v9, Ll2/o;

    .line 67
    .line 68
    check-cast p2, Ljava/lang/Integer;

    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    const/16 p1, 0x31

    .line 74
    .line 75
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    iget-object v2, p0, Lh2/s2;->e:Lx2/s;

    .line 80
    .line 81
    iget-boolean v3, p0, Lh2/s2;->f:Z

    .line 82
    .line 83
    iget-boolean v4, p0, Lh2/s2;->g:Z

    .line 84
    .line 85
    iget-object v5, p0, Lh2/s2;->i:Lay0/a;

    .line 86
    .line 87
    iget-boolean v6, p0, Lh2/s2;->h:Z

    .line 88
    .line 89
    invoke-static/range {v1 .. v10}, Lh2/m3;->m(Ljava/lang/String;Lx2/s;ZZLay0/a;ZLjava/lang/String;Lh2/z1;Ll2/o;I)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
