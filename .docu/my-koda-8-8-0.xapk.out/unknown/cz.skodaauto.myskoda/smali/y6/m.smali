.class public final Ly6/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly6/l;


# instance fields
.field public a:Ly6/q;

.field public b:Ly6/s;

.field public c:Ly6/t;

.field public d:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ly6/o;->a:Ly6/o;

    .line 5
    .line 6
    iput-object v0, p0, Ly6/m;->a:Ly6/q;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput v0, p0, Ly6/m;->d:I

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Ly6/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ly6/m;->a:Ly6/q;

    .line 2
    .line 3
    return-void
.end method

.method public final b()Ly6/q;
    .locals 0

    .line 1
    iget-object p0, p0, Ly6/m;->a:Ly6/q;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy()Ly6/l;
    .locals 2

    .line 1
    new-instance v0, Ly6/m;

    .line 2
    .line 3
    invoke-direct {v0}, Ly6/m;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ly6/m;->a:Ly6/q;

    .line 7
    .line 8
    iput-object v1, v0, Ly6/m;->a:Ly6/q;

    .line 9
    .line 10
    iget-object v1, p0, Ly6/m;->b:Ly6/s;

    .line 11
    .line 12
    iput-object v1, v0, Ly6/m;->b:Ly6/s;

    .line 13
    .line 14
    iget-object v1, p0, Ly6/m;->c:Ly6/t;

    .line 15
    .line 16
    iput-object v1, v0, Ly6/m;->c:Ly6/t;

    .line 17
    .line 18
    iget p0, p0, Ly6/m;->d:I

    .line 19
    .line 20
    iput p0, v0, Ly6/m;->d:I

    .line 21
    .line 22
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "EmittableImage(modifier="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ly6/m;->a:Ly6/q;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", provider="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ly6/m;->b:Ly6/s;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", colorFilterParams="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ly6/m;->c:Ly6/t;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", contentScale="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget p0, p0, Ly6/m;->d:I

    .line 39
    .line 40
    invoke-static {p0}, Lf7/j;->a(I)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const/16 p0, 0x29

    .line 48
    .line 49
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
