.class public final synthetic Lu/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly4/i;
.implements Lyn/f;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLrn/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lu/h;->d:J

    iput-object p3, p0, Lu/h;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lu/m;J)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lu/h;->e:Ljava/lang/Object;

    iput-wide p2, p0, Lu/h;->d:J

    return-void
.end method


# virtual methods
.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lu/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lrn/j;

    .line 4
    .line 5
    check-cast p1, Landroid/database/sqlite/SQLiteDatabase;

    .line 6
    .line 7
    new-instance v1, Landroid/content/ContentValues;

    .line 8
    .line 9
    invoke-direct {v1}, Landroid/content/ContentValues;-><init>()V

    .line 10
    .line 11
    .line 12
    const-string v2, "next_request_ms"

    .line 13
    .line 14
    iget-wide v3, p0, Lu/h;->d:J

    .line 15
    .line 16
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {v1, v2, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, v0, Lrn/j;->a:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v2, v0, Lrn/j;->c:Lon/d;

    .line 26
    .line 27
    invoke-static {v2}, Lbo/a;->a(Lon/d;)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    filled-new-array {p0, v3}, [Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string v3, "transport_contexts"

    .line 40
    .line 41
    const-string v4, "backend_name = ? and priority = ?"

    .line 42
    .line 43
    invoke-virtual {p1, v3, v1, v4, p0}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    const/4 v4, 0x1

    .line 48
    const/4 v5, 0x0

    .line 49
    if-ge p0, v4, :cond_0

    .line 50
    .line 51
    const-string p0, "backend_name"

    .line 52
    .line 53
    iget-object v0, v0, Lrn/j;->a:Ljava/lang/String;

    .line 54
    .line 55
    invoke-virtual {v1, p0, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-static {v2}, Lbo/a;->a(Lon/d;)I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    const-string v0, "priority"

    .line 67
    .line 68
    invoke-virtual {v1, v0, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, v3, v5, v1}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    .line 72
    .line 73
    .line 74
    :cond_0
    return-object v5
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lu/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lu/m;

    .line 4
    .line 5
    new-instance v1, Lu/i;

    .line 6
    .line 7
    iget-wide v2, p0, Lu/h;->d:J

    .line 8
    .line 9
    invoke-direct {v1, v2, v3, p1}, Lu/i;-><init>(JLy4/h;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Lu/m;->h(Lu/l;)V

    .line 13
    .line 14
    .line 15
    new-instance p0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string p1, "waitForSessionUpdateId:"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method
