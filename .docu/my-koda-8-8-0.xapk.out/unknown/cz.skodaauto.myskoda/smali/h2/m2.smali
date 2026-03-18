.class public final synthetic Lh2/m2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:F

.field public final synthetic g:Lay0/n;

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lay0/n;Ll2/b1;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;FLay0/a;Lay0/n;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh2/m2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/m2;->i:Ljava/lang/Object;

    iput-object p2, p0, Lh2/m2;->e:Lay0/n;

    iput-object p3, p0, Lh2/m2;->j:Ljava/lang/Object;

    iput-object p4, p0, Lh2/m2;->k:Ljava/lang/Object;

    iput-object p5, p0, Lh2/m2;->l:Ljava/lang/Object;

    iput p6, p0, Lh2/m2;->f:F

    iput-object p7, p0, Lh2/m2;->m:Llx0/e;

    iput-object p8, p0, Lh2/m2;->g:Lay0/n;

    iput p9, p0, Lh2/m2;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lh2/z1;Lg4/p0;FLt2/b;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lh2/m2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/m2;->i:Ljava/lang/Object;

    iput-object p2, p0, Lh2/m2;->e:Lay0/n;

    iput-object p3, p0, Lh2/m2;->g:Lay0/n;

    iput-object p4, p0, Lh2/m2;->j:Ljava/lang/Object;

    iput-object p5, p0, Lh2/m2;->k:Ljava/lang/Object;

    iput-object p6, p0, Lh2/m2;->l:Ljava/lang/Object;

    iput p7, p0, Lh2/m2;->f:F

    iput-object p8, p0, Lh2/m2;->m:Llx0/e;

    iput p9, p0, Lh2/m2;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lh2/m2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/m2;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/m2;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Ll2/b1;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/m2;->k:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v4, v0

    .line 19
    check-cast v4, Landroidx/datastore/preferences/protobuf/k;

    .line 20
    .line 21
    iget-object v0, p0, Lh2/m2;->l:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v5, v0

    .line 24
    check-cast v5, Ljava/util/List;

    .line 25
    .line 26
    iget-object v0, p0, Lh2/m2;->m:Llx0/e;

    .line 27
    .line 28
    move-object v7, v0

    .line 29
    check-cast v7, Lay0/a;

    .line 30
    .line 31
    move-object v9, p1

    .line 32
    check-cast v9, Ll2/o;

    .line 33
    .line 34
    check-cast p2, Ljava/lang/Integer;

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    iget p1, p0, Lh2/m2;->h:I

    .line 40
    .line 41
    or-int/lit8 p1, p1, 0x1

    .line 42
    .line 43
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 44
    .line 45
    .line 46
    move-result v10

    .line 47
    iget-object v2, p0, Lh2/m2;->e:Lay0/n;

    .line 48
    .line 49
    iget v6, p0, Lh2/m2;->f:F

    .line 50
    .line 51
    iget-object v8, p0, Lh2/m2;->g:Lay0/n;

    .line 52
    .line 53
    invoke-static/range {v1 .. v10}, Lxf0/f0;->a(Ljava/lang/String;Lay0/n;Ll2/b1;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;FLay0/a;Lay0/n;Ll2/o;I)V

    .line 54
    .line 55
    .line 56
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_0
    iget-object v0, p0, Lh2/m2;->i:Ljava/lang/Object;

    .line 60
    .line 61
    move-object v1, v0

    .line 62
    check-cast v1, Lx2/s;

    .line 63
    .line 64
    iget-object v0, p0, Lh2/m2;->j:Ljava/lang/Object;

    .line 65
    .line 66
    move-object v4, v0

    .line 67
    check-cast v4, Lay0/n;

    .line 68
    .line 69
    iget-object v0, p0, Lh2/m2;->k:Ljava/lang/Object;

    .line 70
    .line 71
    move-object v5, v0

    .line 72
    check-cast v5, Lh2/z1;

    .line 73
    .line 74
    iget-object v0, p0, Lh2/m2;->l:Ljava/lang/Object;

    .line 75
    .line 76
    move-object v6, v0

    .line 77
    check-cast v6, Lg4/p0;

    .line 78
    .line 79
    iget-object v0, p0, Lh2/m2;->m:Llx0/e;

    .line 80
    .line 81
    move-object v8, v0

    .line 82
    check-cast v8, Lt2/b;

    .line 83
    .line 84
    move-object v9, p1

    .line 85
    check-cast v9, Ll2/o;

    .line 86
    .line 87
    check-cast p2, Ljava/lang/Integer;

    .line 88
    .line 89
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    iget p1, p0, Lh2/m2;->h:I

    .line 93
    .line 94
    or-int/lit8 p1, p1, 0x1

    .line 95
    .line 96
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 97
    .line 98
    .line 99
    move-result v10

    .line 100
    iget-object v2, p0, Lh2/m2;->e:Lay0/n;

    .line 101
    .line 102
    iget-object v3, p0, Lh2/m2;->g:Lay0/n;

    .line 103
    .line 104
    iget v7, p0, Lh2/m2;->f:F

    .line 105
    .line 106
    invoke-static/range {v1 .. v10}, Lh2/m3;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lh2/z1;Lg4/p0;FLt2/b;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    nop

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
