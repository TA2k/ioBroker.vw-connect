.class public final synthetic Lh2/h6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lh2/r8;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(ZLh2/r8;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lvy0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/h6;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lh2/h6;->e:Lh2/r8;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/h6;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/h6;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/h6;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/h6;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/h6;->j:Lvy0/b0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Ld4/l;

    .line 2
    .line 3
    iget-boolean v0, p0, Lh2/h6;->d:Z

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    new-instance v0, Lb71/i;

    .line 8
    .line 9
    const/16 v1, 0x18

    .line 10
    .line 11
    iget-object v2, p0, Lh2/h6;->i:Lay0/a;

    .line 12
    .line 13
    invoke-direct {v0, v2, v1}, Lb71/i;-><init>(Lay0/a;I)V

    .line 14
    .line 15
    .line 16
    sget-object v1, Ld4/x;->a:[Lhy0/z;

    .line 17
    .line 18
    sget-object v1, Ld4/k;->u:Ld4/z;

    .line 19
    .line 20
    new-instance v2, Ld4/a;

    .line 21
    .line 22
    iget-object v3, p0, Lh2/h6;->f:Ljava/lang/String;

    .line 23
    .line 24
    invoke-direct {v2, v3, v0}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v1, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Lh2/h6;->e:Lh2/r8;

    .line 31
    .line 32
    invoke-virtual {v0}, Lh2/r8;->c()Lh2/s8;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    sget-object v2, Lh2/s8;->f:Lh2/s8;

    .line 37
    .line 38
    iget-object v3, p0, Lh2/h6;->j:Lvy0/b0;

    .line 39
    .line 40
    if-ne v1, v2, :cond_0

    .line 41
    .line 42
    new-instance v1, Lc41/b;

    .line 43
    .line 44
    const/4 v2, 0x6

    .line 45
    invoke-direct {v1, v0, v3, v0, v2}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    sget-object v0, Ld4/k;->s:Ld4/z;

    .line 49
    .line 50
    new-instance v2, Ld4/a;

    .line 51
    .line 52
    iget-object p0, p0, Lh2/h6;->g:Ljava/lang/String;

    .line 53
    .line 54
    invoke-direct {v2, p0, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v0, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    iget-object v1, v0, Lh2/r8;->e:Li2/p;

    .line 62
    .line 63
    invoke-virtual {v1}, Li2/p;->d()Li2/u0;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    iget-object v1, v1, Li2/u0;->a:Ljava/util/Map;

    .line 68
    .line 69
    invoke-interface {v1, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_1

    .line 74
    .line 75
    new-instance v1, Lh2/g0;

    .line 76
    .line 77
    const/4 v2, 0x4

    .line 78
    invoke-direct {v1, v0, v3, v2}, Lh2/g0;-><init>(Lh2/r8;Lvy0/b0;I)V

    .line 79
    .line 80
    .line 81
    sget-object v0, Ld4/k;->t:Ld4/z;

    .line 82
    .line 83
    new-instance v2, Ld4/a;

    .line 84
    .line 85
    iget-object p0, p0, Lh2/h6;->h:Ljava/lang/String;

    .line 86
    .line 87
    invoke-direct {v2, p0, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, v0, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0
.end method
