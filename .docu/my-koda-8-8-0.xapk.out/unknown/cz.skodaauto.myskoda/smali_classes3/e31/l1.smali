.class public final Le31/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Le31/v0;

.field public static final f:[Llx0/i;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Le31/y0;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/util/List;

.field public final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Le31/v0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le31/l1;->Companion:Le31/v0;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Le31/t0;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, v2}, Le31/t0;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v1, 0x5

    .line 21
    new-array v1, v1, [Llx0/i;

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    aput-object v3, v1, v2

    .line 25
    .line 26
    const/4 v2, 0x1

    .line 27
    aput-object v3, v1, v2

    .line 28
    .line 29
    const/4 v2, 0x2

    .line 30
    aput-object v3, v1, v2

    .line 31
    .line 32
    const/4 v2, 0x3

    .line 33
    aput-object v0, v1, v2

    .line 34
    .line 35
    const/4 v0, 0x4

    .line 36
    aput-object v3, v1, v0

    .line 37
    .line 38
    sput-object v1, Le31/l1;->f:[Llx0/i;

    .line 39
    .line 40
    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Le31/y0;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V
    .locals 3

    and-int/lit8 v0, p1, 0xb

    const/4 v1, 0x0

    const/16 v2, 0xb

    if-ne v2, v0, :cond_2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Le31/l1;->a:Ljava/lang/String;

    iput-object p3, p0, Le31/l1;->b:Le31/y0;

    and-int/lit8 p2, p1, 0x4

    if-nez p2, :cond_0

    iput-object v1, p0, Le31/l1;->c:Ljava/lang/String;

    goto :goto_0

    :cond_0
    iput-object p4, p0, Le31/l1;->c:Ljava/lang/String;

    :goto_0
    iput-object p5, p0, Le31/l1;->d:Ljava/util/List;

    and-int/lit8 p1, p1, 0x10

    if-nez p1, :cond_1

    iput-object v1, p0, Le31/l1;->e:Ljava/lang/String;

    return-void

    :cond_1
    iput-object p6, p0, Le31/l1;->e:Ljava/lang/String;

    return-void

    :cond_2
    sget-object p0, Le31/u0;->a:Le31/u0;

    invoke-virtual {p0}, Le31/u0;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    throw v1
.end method

.method public constructor <init>(Ljava/lang/String;Le31/y0;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Le31/l1;->a:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Le31/l1;->b:Le31/y0;

    .line 5
    iput-object p3, p0, Le31/l1;->c:Ljava/lang/String;

    .line 6
    iput-object p4, p0, Le31/l1;->d:Ljava/util/List;

    .line 7
    iput-object p5, p0, Le31/l1;->e:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Le31/l1;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Le31/l1;

    .line 12
    .line 13
    iget-object v1, p0, Le31/l1;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Le31/l1;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Le31/l1;->b:Le31/y0;

    .line 25
    .line 26
    iget-object v3, p1, Le31/l1;->b:Le31/y0;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Le31/l1;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Le31/l1;->c:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Le31/l1;->d:Ljava/util/List;

    .line 47
    .line 48
    iget-object v3, p1, Le31/l1;->d:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object p0, p0, Le31/l1;->e:Ljava/lang/String;

    .line 58
    .line 59
    iget-object p1, p1, Le31/l1;->e:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-nez p0, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Le31/l1;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Le31/l1;->b:Le31/y0;

    .line 11
    .line 12
    invoke-virtual {v2}, Le31/y0;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    const/4 v0, 0x0

    .line 19
    iget-object v3, p0, Le31/l1;->c:Ljava/lang/String;

    .line 20
    .line 21
    if-nez v3, :cond_0

    .line 22
    .line 23
    move v3, v0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    :goto_0
    add-int/2addr v2, v3

    .line 30
    mul-int/2addr v2, v1

    .line 31
    iget-object v3, p0, Le31/l1;->d:Ljava/util/List;

    .line 32
    .line 33
    invoke-static {v2, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget-object p0, p0, Le31/l1;->e:Ljava/lang/String;

    .line 38
    .line 39
    if-nez p0, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    :goto_1
    add-int/2addr v1, v0

    .line 47
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "BookAppointmentBody(appointmentDate="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Le31/l1;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", currentSelection="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Le31/l1;->b:Le31/y0;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", saId="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", services="

    .line 29
    .line 30
    const-string v2, ", serviceMessage="

    .line 31
    .line 32
    iget-object v3, p0, Le31/l1;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-object v4, p0, Le31/l1;->d:Ljava/util/List;

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lu/w;->m(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ")"

    .line 40
    .line 41
    iget-object p0, p0, Le31/l1;->e:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method
