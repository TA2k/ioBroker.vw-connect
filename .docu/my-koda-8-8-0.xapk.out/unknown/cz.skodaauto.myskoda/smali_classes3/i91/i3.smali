.class public final synthetic Li91/i3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Li91/j0;

.field public final synthetic k:Li91/j0;

.field public final synthetic l:Lt1/o0;

.field public final synthetic m:Lt1/n0;

.field public final synthetic n:I

.field public final synthetic o:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZLi91/j0;Li91/j0;Lt1/o0;Lt1/n0;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/i3;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Li91/i3;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Li91/i3;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Li91/i3;->g:Lx2/s;

    .line 11
    .line 12
    iput-boolean p5, p0, Li91/i3;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Li91/i3;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Li91/i3;->j:Li91/j0;

    .line 17
    .line 18
    iput-object p8, p0, Li91/i3;->k:Li91/j0;

    .line 19
    .line 20
    iput-object p9, p0, Li91/i3;->l:Lt1/o0;

    .line 21
    .line 22
    iput-object p10, p0, Li91/i3;->m:Lt1/n0;

    .line 23
    .line 24
    iput p11, p0, Li91/i3;->n:I

    .line 25
    .line 26
    iput p12, p0, Li91/i3;->o:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li91/i3;->n:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v11

    .line 17
    iget-object v0, p0, Li91/i3;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Li91/i3;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v2, p0, Li91/i3;->f:Lay0/k;

    .line 22
    .line 23
    iget-object v3, p0, Li91/i3;->g:Lx2/s;

    .line 24
    .line 25
    iget-boolean v4, p0, Li91/i3;->h:Z

    .line 26
    .line 27
    iget-boolean v5, p0, Li91/i3;->i:Z

    .line 28
    .line 29
    iget-object v6, p0, Li91/i3;->j:Li91/j0;

    .line 30
    .line 31
    iget-object v7, p0, Li91/i3;->k:Li91/j0;

    .line 32
    .line 33
    iget-object v8, p0, Li91/i3;->l:Lt1/o0;

    .line 34
    .line 35
    iget-object v9, p0, Li91/i3;->m:Lt1/n0;

    .line 36
    .line 37
    iget v12, p0, Li91/i3;->o:I

    .line 38
    .line 39
    invoke-static/range {v0 .. v12}, Li91/m3;->a(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZLi91/j0;Li91/j0;Lt1/o0;Lt1/n0;Ll2/o;II)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0
.end method
