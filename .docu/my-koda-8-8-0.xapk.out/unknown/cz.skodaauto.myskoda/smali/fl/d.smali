.class public final Lfl/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final a:Landroid/content/SharedPreferences;

.field public final b:Ltj/h;

.field public final c:Ltj/h;


# direct methods
.method public constructor <init>(Landroid/content/SharedPreferences;Ltj/h;Ltj/h;)V
    .locals 5

    .line 1
    const-string v0, "sharedPreferences"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lfl/d;->a:Landroid/content/SharedPreferences;

    .line 10
    .line 11
    iput-object p2, p0, Lfl/d;->b:Ltj/h;

    .line 12
    .line 13
    iput-object p3, p0, Lfl/d;->c:Ltj/h;

    .line 14
    .line 15
    const-string p0, "X-Consent"

    .line 16
    .line 17
    const/4 p3, 0x0

    .line 18
    invoke-interface {p1, p0, p3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    invoke-static {p0}, Lfl/d;->a(Ljava/lang/String;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    instance-of p1, p0, Llx0/n;

    .line 29
    .line 30
    if-nez p1, :cond_1

    .line 31
    .line 32
    check-cast p0, Ltb/t;

    .line 33
    .line 34
    sget-object p1, Lgi/a;->d:Lgi/a;

    .line 35
    .line 36
    new-instance v0, Lfl/c;

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    invoke-direct {v0, p0, v1}, Lfl/c;-><init>(Ltb/t;I)V

    .line 40
    .line 41
    .line 42
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 43
    .line 44
    const-class v2, Lfl/d;

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    const/16 v3, 0x24

    .line 51
    .line 52
    invoke-static {v2, v3}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    const/16 v4, 0x2e

    .line 57
    .line 58
    invoke-static {v4, v3, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-nez v4, :cond_0

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    const-string v2, "Kt"

    .line 70
    .line 71
    invoke-static {v3, v2}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    :goto_0
    invoke-static {v2, p1, v1, p3, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p2, p0}, Ltj/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    :cond_1
    return-void
.end method

.method public static a(Ljava/lang/String;)Ljava/lang/Object;
    .locals 3

    .line 1
    :try_start_0
    sget-object v0, Lfl/i;->a:Lvz0/t;

    .line 2
    .line 3
    iget-object v1, v0, Lvz0/d;->b:Lwq/f;

    .line 4
    .line 5
    const-class v2, Ltb/t;

    .line 6
    .line 7
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-static {v1, v2}, Ljp/mg;->d(Lwq/f;Lhy0/a0;)Lqz0/a;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lqz0/a;

    .line 16
    .line 17
    invoke-virtual {v0, p0, v1}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ltb/t;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    return-object p0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 9

    .line 1
    check-cast p1, Li01/f;

    .line 2
    .line 3
    iget-object v0, p1, Li01/f;->e:Ld01/k0;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object v0, p1, Ld01/t0;->i:Ld01/y;

    .line 10
    .line 11
    const-string v1, "X-Consent"

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-static {v0}, Lfl/d;->a(Ljava/lang/String;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    instance-of v3, v2, Llx0/n;

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    check-cast v2, Ltb/t;

    .line 28
    .line 29
    sget-object v3, Lgi/a;->d:Lgi/a;

    .line 30
    .line 31
    new-instance v4, Lfl/c;

    .line 32
    .line 33
    const/4 v5, 0x1

    .line 34
    invoke-direct {v4, v2, v5}, Lfl/c;-><init>(Ltb/t;I)V

    .line 35
    .line 36
    .line 37
    sget-object v5, Lgi/b;->e:Lgi/b;

    .line 38
    .line 39
    const-class v6, Lfl/d;

    .line 40
    .line 41
    invoke-virtual {v6}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    const/16 v7, 0x24

    .line 46
    .line 47
    invoke-static {v6, v7}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    const/16 v8, 0x2e

    .line 52
    .line 53
    invoke-static {v8, v7, v7}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    if-nez v8, :cond_0

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_0
    const-string v6, "Kt"

    .line 65
    .line 66
    invoke-static {v7, v6}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    :goto_0
    const/4 v7, 0x0

    .line 71
    invoke-static {v6, v3, v5, v7, v4}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 72
    .line 73
    .line 74
    iget-object v3, p0, Lfl/d;->a:Landroid/content/SharedPreferences;

    .line 75
    .line 76
    invoke-interface {v3}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-interface {v3, v1, v0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 81
    .line 82
    .line 83
    invoke-interface {v3}, Landroid/content/SharedPreferences$Editor;->commit()Z

    .line 84
    .line 85
    .line 86
    iget-object v0, p0, Lfl/d;->b:Ltj/h;

    .line 87
    .line 88
    invoke-virtual {v0, v2}, Ltj/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    :cond_1
    iget v0, p1, Ld01/t0;->g:I

    .line 92
    .line 93
    const/16 v1, 0x1ac

    .line 94
    .line 95
    iget-object p0, p0, Lfl/d;->c:Ltj/h;

    .line 96
    .line 97
    if-ne v0, v1, :cond_2

    .line 98
    .line 99
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 100
    .line 101
    invoke-virtual {p0, v0}, Ltj/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    :cond_2
    iget-boolean v0, p1, Ld01/t0;->t:Z

    .line 105
    .line 106
    if-eqz v0, :cond_3

    .line 107
    .line 108
    iget-object v0, p1, Ld01/t0;->d:Ld01/k0;

    .line 109
    .line 110
    iget-object v0, v0, Ld01/k0;->a:Ld01/a0;

    .line 111
    .line 112
    invoke-virtual {v0}, Ld01/a0;->b()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    const-string v1, "/consent/complete"

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    if-eqz v0, :cond_3

    .line 123
    .line 124
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {p0, v0}, Ltj/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    :cond_3
    return-object p1
.end method
