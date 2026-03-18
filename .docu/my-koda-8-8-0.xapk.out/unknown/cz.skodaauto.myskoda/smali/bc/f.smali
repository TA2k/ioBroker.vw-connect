.class public final synthetic Lbc/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Llx0/l;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:J

.field public final synthetic h:Z

.field public final synthetic i:J

.field public final synthetic j:Lmw/c;

.field public final synthetic k:Lbc/b;

.field public final synthetic l:Z

.field public final synthetic m:I

.field public final synthetic n:I

.field public final synthetic o:I


# direct methods
.method public synthetic constructor <init>(Llx0/l;Lx2/s;Lay0/k;JZJLmw/c;Lbc/b;ZIII)V
    .locals 1

    .line 1
    sget-object v0, Lbc/k;->d:[Lbc/k;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lbc/f;->d:Llx0/l;

    .line 7
    .line 8
    iput-object p2, p0, Lbc/f;->e:Lx2/s;

    .line 9
    .line 10
    iput-object p3, p0, Lbc/f;->f:Lay0/k;

    .line 11
    .line 12
    iput-wide p4, p0, Lbc/f;->g:J

    .line 13
    .line 14
    iput-boolean p6, p0, Lbc/f;->h:Z

    .line 15
    .line 16
    iput-wide p7, p0, Lbc/f;->i:J

    .line 17
    .line 18
    iput-object p9, p0, Lbc/f;->j:Lmw/c;

    .line 19
    .line 20
    iput-object p10, p0, Lbc/f;->k:Lbc/b;

    .line 21
    .line 22
    iput-boolean p11, p0, Lbc/f;->l:Z

    .line 23
    .line 24
    iput p12, p0, Lbc/f;->m:I

    .line 25
    .line 26
    iput p13, p0, Lbc/f;->n:I

    .line 27
    .line 28
    iput p14, p0, Lbc/f;->o:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lbc/k;->d:[Lbc/k;

    .line 4
    .line 5
    move-object/from16 v13, p1

    .line 6
    .line 7
    check-cast v13, Ll2/o;

    .line 8
    .line 9
    move-object/from16 v1, p2

    .line 10
    .line 11
    check-cast v1, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    iget v1, v0, Lbc/f;->m:I

    .line 17
    .line 18
    or-int/lit8 v1, v1, 0x1

    .line 19
    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v14

    .line 24
    iget v1, v0, Lbc/f;->n:I

    .line 25
    .line 26
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result v15

    .line 30
    iget-object v2, v0, Lbc/f;->d:Llx0/l;

    .line 31
    .line 32
    iget-object v3, v0, Lbc/f;->e:Lx2/s;

    .line 33
    .line 34
    iget-object v4, v0, Lbc/f;->f:Lay0/k;

    .line 35
    .line 36
    iget-wide v5, v0, Lbc/f;->g:J

    .line 37
    .line 38
    iget-boolean v7, v0, Lbc/f;->h:Z

    .line 39
    .line 40
    iget-wide v8, v0, Lbc/f;->i:J

    .line 41
    .line 42
    iget-object v10, v0, Lbc/f;->j:Lmw/c;

    .line 43
    .line 44
    iget-object v11, v0, Lbc/f;->k:Lbc/b;

    .line 45
    .line 46
    iget-boolean v12, v0, Lbc/f;->l:Z

    .line 47
    .line 48
    iget v0, v0, Lbc/f;->o:I

    .line 49
    .line 50
    move/from16 v16, v0

    .line 51
    .line 52
    invoke-static/range {v2 .. v16}, Lbc/h;->a(Llx0/l;Lx2/s;Lay0/k;JZJLmw/c;Lbc/b;ZLl2/o;III)V

    .line 53
    .line 54
    .line 55
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object v0
.end method
