.class public final synthetic Lcv0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lbv0/c;

.field public final synthetic f:Le1/n1;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Lbv0/c;Le1/n1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/a;II)V
    .locals 0

    .line 1
    iput p13, p0, Lcv0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcv0/b;->e:Lbv0/c;

    .line 4
    .line 5
    iput-object p2, p0, Lcv0/b;->f:Le1/n1;

    .line 6
    .line 7
    iput-object p3, p0, Lcv0/b;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lcv0/b;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lcv0/b;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Lcv0/b;->j:Lay0/a;

    .line 14
    .line 15
    iput-object p7, p0, Lcv0/b;->k:Lay0/a;

    .line 16
    .line 17
    iput-object p8, p0, Lcv0/b;->l:Lay0/a;

    .line 18
    .line 19
    iput-object p9, p0, Lcv0/b;->m:Lay0/k;

    .line 20
    .line 21
    iput-object p10, p0, Lcv0/b;->n:Lay0/k;

    .line 22
    .line 23
    iput-object p11, p0, Lcv0/b;->o:Lay0/a;

    .line 24
    .line 25
    iput p12, p0, Lcv0/b;->p:I

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lcv0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v12, p1

    .line 7
    check-cast v12, Ll2/o;

    .line 8
    .line 9
    move-object/from16 v0, p2

    .line 10
    .line 11
    check-cast v0, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    iget v0, p0, Lcv0/b;->p:I

    .line 17
    .line 18
    or-int/lit8 v0, v0, 0x1

    .line 19
    .line 20
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v13

    .line 24
    iget-object v1, p0, Lcv0/b;->e:Lbv0/c;

    .line 25
    .line 26
    iget-object v2, p0, Lcv0/b;->f:Le1/n1;

    .line 27
    .line 28
    iget-object v3, p0, Lcv0/b;->g:Lay0/a;

    .line 29
    .line 30
    iget-object v4, p0, Lcv0/b;->h:Lay0/a;

    .line 31
    .line 32
    iget-object v5, p0, Lcv0/b;->i:Lay0/a;

    .line 33
    .line 34
    iget-object v6, p0, Lcv0/b;->j:Lay0/a;

    .line 35
    .line 36
    iget-object v7, p0, Lcv0/b;->k:Lay0/a;

    .line 37
    .line 38
    iget-object v8, p0, Lcv0/b;->l:Lay0/a;

    .line 39
    .line 40
    iget-object v9, p0, Lcv0/b;->m:Lay0/k;

    .line 41
    .line 42
    iget-object v10, p0, Lcv0/b;->n:Lay0/k;

    .line 43
    .line 44
    iget-object v11, p0, Lcv0/b;->o:Lay0/a;

    .line 45
    .line 46
    invoke-static/range {v1 .. v13}, Ljp/oe;->c(Lbv0/c;Le1/n1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_0
    move-object v11, p1

    .line 53
    check-cast v11, Ll2/o;

    .line 54
    .line 55
    move-object/from16 v0, p2

    .line 56
    .line 57
    check-cast v0, Ljava/lang/Integer;

    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    iget v0, p0, Lcv0/b;->p:I

    .line 63
    .line 64
    or-int/lit8 v0, v0, 0x1

    .line 65
    .line 66
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result v12

    .line 70
    iget-object v0, p0, Lcv0/b;->e:Lbv0/c;

    .line 71
    .line 72
    iget-object v1, p0, Lcv0/b;->f:Le1/n1;

    .line 73
    .line 74
    iget-object v2, p0, Lcv0/b;->g:Lay0/a;

    .line 75
    .line 76
    iget-object v3, p0, Lcv0/b;->h:Lay0/a;

    .line 77
    .line 78
    iget-object v4, p0, Lcv0/b;->i:Lay0/a;

    .line 79
    .line 80
    iget-object v5, p0, Lcv0/b;->j:Lay0/a;

    .line 81
    .line 82
    iget-object v6, p0, Lcv0/b;->k:Lay0/a;

    .line 83
    .line 84
    iget-object v7, p0, Lcv0/b;->l:Lay0/a;

    .line 85
    .line 86
    iget-object v8, p0, Lcv0/b;->m:Lay0/k;

    .line 87
    .line 88
    iget-object v9, p0, Lcv0/b;->n:Lay0/k;

    .line 89
    .line 90
    iget-object v10, p0, Lcv0/b;->o:Lay0/a;

    .line 91
    .line 92
    invoke-static/range {v0 .. v12}, Ljp/oe;->c(Lbv0/c;Le1/n1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
