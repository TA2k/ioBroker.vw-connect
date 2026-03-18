.class public final Llr/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Llr/b;->d:I

    iput-object p2, p0, Llr/b;->e:Ljava/lang/Object;

    iput-object p3, p0, Llr/b;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lhs/k;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Llr/b;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llr/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 2
    iput p4, p0, Llr/b;->d:I

    iput-object p1, p0, Llr/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Llr/b;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llp/lg;Lpv/g;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Llr/b;->d:I

    sget-object v0, Llp/ub;->e:Llp/ub;

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llr/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Llr/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lpv/g;Lvp/z3;Ljava/lang/Runnable;)V
    .locals 0

    const/16 p1, 0x18

    iput p1, p0, Llr/b;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llr/b;->e:Ljava/lang/Object;

    iput-object p3, p0, Llr/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/d3;Lvp/r2;)V
    .locals 1

    const/16 v0, 0x15

    iput v0, p0, Llr/b;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llr/b;->e:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Llr/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/j2;Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 1

    const/16 v0, 0x13

    iput v0, p0, Llr/b;->d:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llr/b;->e:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Llr/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/x0;Lcom/google/android/gms/internal/measurement/c0;Lvp/x0;)V
    .locals 0

    const/16 p3, 0x11

    iput p3, p0, Llr/b;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llr/b;->e:Ljava/lang/Object;

    iput-object p1, p0, Llr/b;->f:Ljava/lang/Object;

    return-void
.end method

.method private final a()V
    .locals 5

    .line 1
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llb/b;

    .line 4
    .line 5
    iget-object v0, v0, Llb/b;->d:Lfb/u;

    .line 6
    .line 7
    iget-object v0, v0, Lfb/u;->f:Lfb/e;

    .line 8
    .line 9
    iget-object v1, p0, Llr/b;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Ljava/lang/String;

    .line 12
    .line 13
    iget-object v2, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 14
    .line 15
    monitor-enter v2

    .line 16
    :try_start_0
    invoke-virtual {v0, v1}, Lfb/e;->c(Ljava/lang/String;)Lfb/f0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    iget-object v0, v0, Lfb/f0;->a:Lmb/o;

    .line 23
    .line 24
    monitor-exit v2

    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    const/4 v0, 0x0

    .line 30
    :goto_0
    if-eqz v0, :cond_1

    .line 31
    .line 32
    sget-object v1, Leb/e;->j:Leb/e;

    .line 33
    .line 34
    iget-object v2, v0, Lmb/o;->j:Leb/e;

    .line 35
    .line 36
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-nez v1, :cond_1

    .line 41
    .line 42
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Llb/b;

    .line 45
    .line 46
    iget-object v1, v1, Llb/b;->f:Ljava/lang/Object;

    .line 47
    .line 48
    monitor-enter v1

    .line 49
    :try_start_1
    iget-object v2, p0, Llr/b;->f:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v2, Llb/b;

    .line 52
    .line 53
    iget-object v2, v2, Llb/b;->i:Ljava/util/HashMap;

    .line 54
    .line 55
    invoke-static {v0}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-virtual {v2, v3, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    iget-object v2, p0, Llr/b;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v2, Llb/b;

    .line 65
    .line 66
    iget-object v3, v2, Llb/b;->k:Laq/m;

    .line 67
    .line 68
    iget-object v4, v2, Llb/b;->e:Lob/a;

    .line 69
    .line 70
    iget-object v4, v4, Lob/a;->b:Lvy0/x;

    .line 71
    .line 72
    invoke-static {v3, v0, v4, v2}, Lib/j;->a(Laq/m;Lmb/o;Lvy0/x;Lib/f;)Lvy0/x1;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Llb/b;

    .line 79
    .line 80
    iget-object p0, p0, Llb/b;->j:Ljava/util/HashMap;

    .line 81
    .line 82
    invoke-static {v0}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-virtual {p0, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    monitor-exit v1

    .line 90
    return-void

    .line 91
    :catchall_1
    move-exception p0

    .line 92
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 93
    throw p0

    .line 94
    :cond_1
    return-void

    .line 95
    :goto_1
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 96
    throw p0
.end method

.method private final b()V
    .locals 8

    .line 1
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llo/p;

    .line 4
    .line 5
    iget-boolean v0, v0, Llo/p;->e:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_3

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Llo/g0;

    .line 14
    .line 15
    iget-object v0, v0, Llo/g0;->b:Ljo/b;

    .line 16
    .line 17
    iget v1, v0, Ljo/b;->e:I

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    const/4 v3, 0x0

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iget-object v1, v0, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v1, Llo/p;

    .line 30
    .line 31
    iget-object v4, v1, Llo/p;->d:Ljava/lang/Object;

    .line 32
    .line 33
    invoke-virtual {v1}, Llo/p;->a()Landroid/app/Activity;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iget-object v0, v0, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 38
    .line 39
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Llo/g0;

    .line 45
    .line 46
    iget p0, p0, Llo/g0;->a:I

    .line 47
    .line 48
    sget v5, Lcom/google/android/gms/common/api/GoogleApiActivity;->e:I

    .line 49
    .line 50
    const-class v5, Lcom/google/android/gms/common/api/GoogleApiActivity;

    .line 51
    .line 52
    new-instance v6, Landroid/content/Intent;

    .line 53
    .line 54
    invoke-direct {v6, v1, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 55
    .line 56
    .line 57
    const-string v1, "pending_intent"

    .line 58
    .line 59
    invoke-virtual {v6, v1, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 60
    .line 61
    .line 62
    const-string v0, "failing_client_id"

    .line 63
    .line 64
    invoke-virtual {v6, v0, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 65
    .line 66
    .line 67
    const-string p0, "notify_manager"

    .line 68
    .line 69
    invoke-virtual {v6, p0, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 70
    .line 71
    .line 72
    invoke-interface {v4, v6, v2}, Llo/j;->startActivityForResult(Landroid/content/Intent;I)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_1
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v1, Llo/p;

    .line 79
    .line 80
    invoke-virtual {v1}, Llo/p;->a()Landroid/app/Activity;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    iget v5, v0, Ljo/b;->e:I

    .line 85
    .line 86
    iget-object v1, v1, Llo/p;->h:Ljo/e;

    .line 87
    .line 88
    const/4 v6, 0x0

    .line 89
    invoke-virtual {v1, v4, v6, v5}, Ljo/f;->b(Landroid/content/Context;Ljava/lang/String;I)Landroid/content/Intent;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    if-eqz v1, :cond_2

    .line 94
    .line 95
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v1, Llo/p;

    .line 98
    .line 99
    invoke-virtual {v1}, Llo/p;->a()Landroid/app/Activity;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    iget-object v3, v1, Llo/p;->d:Ljava/lang/Object;

    .line 104
    .line 105
    iget v0, v0, Ljo/b;->e:I

    .line 106
    .line 107
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast p0, Llo/p;

    .line 110
    .line 111
    iget-object v1, v1, Llo/p;->h:Ljo/e;

    .line 112
    .line 113
    invoke-virtual {v1, v2, v3, v0, p0}, Ljo/e;->h(Landroid/app/Activity;Llo/j;ILandroid/content/DialogInterface$OnCancelListener;)V

    .line 114
    .line 115
    .line 116
    return-void

    .line 117
    :cond_2
    iget v1, v0, Ljo/b;->e:I

    .line 118
    .line 119
    const/16 v4, 0x12

    .line 120
    .line 121
    if-ne v1, v4, :cond_8

    .line 122
    .line 123
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Llo/p;

    .line 126
    .line 127
    iget-object v1, v0, Llo/p;->h:Ljo/e;

    .line 128
    .line 129
    invoke-virtual {v0}, Llo/p;->a()Landroid/app/Activity;

    .line 130
    .line 131
    .line 132
    move-result-object v5

    .line 133
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 134
    .line 135
    .line 136
    new-instance v1, Landroid/widget/ProgressBar;

    .line 137
    .line 138
    const v7, 0x101007a

    .line 139
    .line 140
    .line 141
    invoke-direct {v1, v5, v6, v7}, Landroid/widget/ProgressBar;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v1, v2}, Landroid/widget/ProgressBar;->setIndeterminate(Z)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v1, v3}, Landroid/view/View;->setVisibility(I)V

    .line 148
    .line 149
    .line 150
    new-instance v2, Landroid/app/AlertDialog$Builder;

    .line 151
    .line 152
    invoke-direct {v2, v5}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v2, v1}, Landroid/app/AlertDialog$Builder;->setView(Landroid/view/View;)Landroid/app/AlertDialog$Builder;

    .line 156
    .line 157
    .line 158
    invoke-static {v5, v4}, Lno/r;->c(Landroid/content/Context;I)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    invoke-virtual {v2, v1}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    .line 163
    .line 164
    .line 165
    const-string v1, ""

    .line 166
    .line 167
    invoke-virtual {v2, v1, v6}, Landroid/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v2}, Landroid/app/AlertDialog$Builder;->create()Landroid/app/AlertDialog;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    const-string v2, "GooglePlayServicesUpdatingDialog"

    .line 175
    .line 176
    invoke-static {v5, v1, v2, v0}, Ljo/e;->f(Landroid/app/Activity;Landroid/app/AlertDialog;Ljava/lang/String;Landroid/content/DialogInterface$OnCancelListener;)V

    .line 177
    .line 178
    .line 179
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v0, Llo/p;

    .line 182
    .line 183
    invoke-virtual {v0}, Llo/p;->a()Landroid/app/Activity;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    new-instance v4, Lb81/b;

    .line 192
    .line 193
    const/16 v5, 0x10

    .line 194
    .line 195
    invoke-direct {v4, p0, v1, v3, v5}, Lb81/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 196
    .line 197
    .line 198
    iget-object v0, v0, Llo/p;->h:Ljo/e;

    .line 199
    .line 200
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 201
    .line 202
    .line 203
    new-instance v0, Landroid/content/IntentFilter;

    .line 204
    .line 205
    const-string v5, "android.intent.action.PACKAGE_ADDED"

    .line 206
    .line 207
    invoke-direct {v0, v5}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    const-string v5, "package"

    .line 211
    .line 212
    invoke-virtual {v0, v5}, Landroid/content/IntentFilter;->addDataScheme(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    new-instance v5, Lcom/google/firebase/messaging/y;

    .line 216
    .line 217
    invoke-direct {v5, v4}, Lcom/google/firebase/messaging/y;-><init>(Lb81/b;)V

    .line 218
    .line 219
    .line 220
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 221
    .line 222
    const/16 v7, 0x21

    .line 223
    .line 224
    if-lt v4, v7, :cond_4

    .line 225
    .line 226
    if-lt v4, v7, :cond_3

    .line 227
    .line 228
    const/4 v3, 0x2

    .line 229
    :cond_3
    invoke-virtual {v2, v5, v0, v3}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)Landroid/content/Intent;

    .line 230
    .line 231
    .line 232
    goto :goto_0

    .line 233
    :cond_4
    invoke-virtual {v2, v5, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 234
    .line 235
    .line 236
    :goto_0
    iput-object v2, v5, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;

    .line 237
    .line 238
    invoke-static {v2}, Ljo/h;->c(Landroid/content/Context;)Z

    .line 239
    .line 240
    .line 241
    move-result v0

    .line 242
    if-nez v0, :cond_7

    .line 243
    .line 244
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast p0, Llo/p;

    .line 247
    .line 248
    iget-object v0, p0, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 249
    .line 250
    invoke-virtual {v0, v6}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    iget-object p0, p0, Llo/p;->j:Llo/g;

    .line 254
    .line 255
    iget-object p0, p0, Llo/g;->q:Lbp/c;

    .line 256
    .line 257
    const/4 v0, 0x3

    .line 258
    invoke-virtual {p0, v0}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    invoke-virtual {p0, v0}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 263
    .line 264
    .line 265
    invoke-virtual {v1}, Landroid/app/Dialog;->isShowing()Z

    .line 266
    .line 267
    .line 268
    move-result p0

    .line 269
    if-eqz p0, :cond_5

    .line 270
    .line 271
    invoke-virtual {v1}, Landroid/app/Dialog;->dismiss()V

    .line 272
    .line 273
    .line 274
    :cond_5
    monitor-enter v5

    .line 275
    :try_start_0
    iget-object p0, v5, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;

    .line 276
    .line 277
    if-eqz p0, :cond_6

    .line 278
    .line 279
    invoke-virtual {p0, v5}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 280
    .line 281
    .line 282
    goto :goto_1

    .line 283
    :catchall_0
    move-exception p0

    .line 284
    goto :goto_2

    .line 285
    :cond_6
    :goto_1
    iput-object v6, v5, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 286
    .line 287
    monitor-exit v5

    .line 288
    return-void

    .line 289
    :goto_2
    :try_start_1
    monitor-exit v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 290
    throw p0

    .line 291
    :cond_7
    :goto_3
    return-void

    .line 292
    :cond_8
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 293
    .line 294
    check-cast v1, Llo/p;

    .line 295
    .line 296
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast p0, Llo/g0;

    .line 299
    .line 300
    iget p0, p0, Llo/g0;->a:I

    .line 301
    .line 302
    iget-object v2, v1, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 303
    .line 304
    invoke-virtual {v2, v6}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    iget-object v1, v1, Llo/p;->j:Llo/g;

    .line 308
    .line 309
    invoke-virtual {v1, v0, p0}, Llo/g;->h(Ljo/b;I)V

    .line 310
    .line 311
    .line 312
    return-void
.end method

.method private final c()V
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Llr/b;->f:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v3, v1

    .line 6
    check-cast v3, Lvp/g1;

    .line 7
    .line 8
    iget-object v0, v0, Llr/b;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lvp/v1;

    .line 11
    .line 12
    iget-object v1, v3, Lvp/g1;->j:Lvp/e1;

    .line 13
    .line 14
    iget-object v8, v3, Lvp/g1;->i:Lvp/p0;

    .line 15
    .line 16
    iget-object v9, v3, Lvp/g1;->h:Lvp/w0;

    .line 17
    .line 18
    iget-object v10, v3, Lvp/g1;->l:Lvp/d4;

    .line 19
    .line 20
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Lvp/e1;->a0()V

    .line 24
    .line 25
    .line 26
    iget-object v1, v3, Lvp/g1;->g:Lvp/h;

    .line 27
    .line 28
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v2, Lvp/g1;

    .line 31
    .line 32
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    new-instance v2, Lvp/q;

    .line 36
    .line 37
    invoke-direct {v2, v3}, Lvp/n1;-><init>(Lvp/g1;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v2}, Lvp/n1;->d0()V

    .line 41
    .line 42
    .line 43
    iput-object v2, v3, Lvp/g1;->v:Lvp/q;

    .line 44
    .line 45
    iget-object v11, v0, Lvp/v1;->d:Lcom/google/android/gms/internal/measurement/u0;

    .line 46
    .line 47
    if-nez v11, :cond_0

    .line 48
    .line 49
    const-wide/16 v6, 0x0

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    iget-wide v4, v11, Lcom/google/android/gms/internal/measurement/u0;->d:J

    .line 53
    .line 54
    move-wide v6, v4

    .line 55
    :goto_0
    new-instance v2, Lvp/h0;

    .line 56
    .line 57
    iget-wide v4, v0, Lvp/v1;->c:J

    .line 58
    .line 59
    invoke-direct/range {v2 .. v7}, Lvp/h0;-><init>(Lvp/g1;JJ)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2}, Lvp/b0;->c0()V

    .line 63
    .line 64
    .line 65
    iput-object v2, v3, Lvp/g1;->w:Lvp/h0;

    .line 66
    .line 67
    new-instance v0, Lvp/j0;

    .line 68
    .line 69
    invoke-direct {v0, v3}, Lvp/j0;-><init>(Lvp/g1;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Lvp/b0;->c0()V

    .line 73
    .line 74
    .line 75
    iput-object v0, v3, Lvp/g1;->t:Lvp/j0;

    .line 76
    .line 77
    new-instance v0, Lvp/d3;

    .line 78
    .line 79
    invoke-direct {v0, v3}, Lvp/d3;-><init>(Lvp/g1;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v0}, Lvp/b0;->c0()V

    .line 83
    .line 84
    .line 85
    iput-object v0, v3, Lvp/g1;->u:Lvp/d3;

    .line 86
    .line 87
    iget-boolean v0, v10, Lvp/n1;->f:Z

    .line 88
    .line 89
    iget-object v4, v10, Lap0/o;->e:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v4, Lvp/g1;

    .line 92
    .line 93
    const-string v5, "Can\'t initialize twice"

    .line 94
    .line 95
    if-nez v0, :cond_48

    .line 96
    .line 97
    invoke-virtual {v10}, Lap0/o;->a0()V

    .line 98
    .line 99
    .line 100
    new-instance v0, Ljava/security/SecureRandom;

    .line 101
    .line 102
    invoke-direct {v0}, Ljava/security/SecureRandom;-><init>()V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/util/Random;->nextLong()J

    .line 106
    .line 107
    .line 108
    move-result-wide v6

    .line 109
    const-wide/16 v14, 0x0

    .line 110
    .line 111
    cmp-long v16, v6, v14

    .line 112
    .line 113
    if-nez v16, :cond_1

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/util/Random;->nextLong()J

    .line 116
    .line 117
    .line 118
    move-result-wide v6

    .line 119
    cmp-long v0, v6, v14

    .line 120
    .line 121
    if-nez v0, :cond_1

    .line 122
    .line 123
    iget-object v0, v10, Lap0/o;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lvp/g1;

    .line 126
    .line 127
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 128
    .line 129
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 130
    .line 131
    .line 132
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 133
    .line 134
    const-string v14, "Utils falling back to Random for random id"

    .line 135
    .line 136
    invoke-virtual {v0, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    :cond_1
    iget-object v0, v10, Lvp/d4;->h:Ljava/util/concurrent/atomic/AtomicLong;

    .line 140
    .line 141
    invoke-virtual {v0, v6, v7}, Ljava/util/concurrent/atomic/AtomicLong;->set(J)V

    .line 142
    .line 143
    .line 144
    iget-object v0, v4, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 147
    .line 148
    .line 149
    const/4 v6, 0x1

    .line 150
    iput-boolean v6, v10, Lvp/n1;->f:Z

    .line 151
    .line 152
    iget-boolean v0, v9, Lvp/n1;->f:Z

    .line 153
    .line 154
    if-nez v0, :cond_47

    .line 155
    .line 156
    iget-object v0, v9, Lap0/o;->e:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v0, Lvp/g1;

    .line 159
    .line 160
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 161
    .line 162
    const-string v7, "com.google.android.gms.measurement.prefs"

    .line 163
    .line 164
    const/4 v14, 0x0

    .line 165
    invoke-virtual {v0, v7, v14}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    iput-object v0, v9, Lvp/w0;->g:Landroid/content/SharedPreferences;

    .line 170
    .line 171
    const-string v7, "has_been_opened"

    .line 172
    .line 173
    invoke-interface {v0, v7, v14}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    iput-boolean v0, v9, Lvp/w0;->v:Z

    .line 178
    .line 179
    if-nez v0, :cond_2

    .line 180
    .line 181
    iget-object v0, v9, Lvp/w0;->g:Landroid/content/SharedPreferences;

    .line 182
    .line 183
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    const/4 v14, 0x1

    .line 188
    invoke-interface {v0, v7, v14}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 189
    .line 190
    .line 191
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 192
    .line 193
    .line 194
    :cond_2
    new-instance v0, Lgb/d;

    .line 195
    .line 196
    sget-object v7, Lvp/z;->d:Lvp/y;

    .line 197
    .line 198
    const/4 v14, 0x0

    .line 199
    invoke-virtual {v7, v14}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v7

    .line 203
    check-cast v7, Ljava/lang/Long;

    .line 204
    .line 205
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 206
    .line 207
    .line 208
    move-result-wide v14

    .line 209
    const-wide/16 v16, 0x0

    .line 210
    .line 211
    const-wide/16 v12, 0x0

    .line 212
    .line 213
    invoke-static {v12, v13, v14, v15}, Ljava/lang/Math;->max(JJ)J

    .line 214
    .line 215
    .line 216
    move-result-wide v12

    .line 217
    invoke-direct {v0, v9, v12, v13}, Lgb/d;-><init>(Lvp/w0;J)V

    .line 218
    .line 219
    .line 220
    iput-object v0, v9, Lvp/w0;->i:Lgb/d;

    .line 221
    .line 222
    iget-object v0, v9, Lap0/o;->e:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast v0, Lvp/g1;

    .line 225
    .line 226
    iget-object v0, v0, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 227
    .line 228
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 229
    .line 230
    .line 231
    iput-boolean v6, v9, Lvp/n1;->f:Z

    .line 232
    .line 233
    iget-object v7, v3, Lvp/g1;->w:Lvp/h0;

    .line 234
    .line 235
    iget-boolean v0, v7, Lvp/b0;->f:Z

    .line 236
    .line 237
    if-nez v0, :cond_46

    .line 238
    .line 239
    iget-object v0, v7, Lap0/o;->e:Ljava/lang/Object;

    .line 240
    .line 241
    move-object v12, v0

    .line 242
    check-cast v12, Lvp/g1;

    .line 243
    .line 244
    iget-object v0, v12, Lvp/g1;->i:Lvp/p0;

    .line 245
    .line 246
    iget-object v13, v12, Lvp/g1;->i:Lvp/p0;

    .line 247
    .line 248
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 249
    .line 250
    .line 251
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 252
    .line 253
    iget-wide v14, v7, Lvp/h0;->n:J

    .line 254
    .line 255
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 256
    .line 257
    .line 258
    move-result-object v14

    .line 259
    move-object/from16 p0, v4

    .line 260
    .line 261
    move-object v15, v5

    .line 262
    iget-wide v4, v7, Lvp/h0;->m:J

    .line 263
    .line 264
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 265
    .line 266
    .line 267
    move-result-object v4

    .line 268
    const-string v5, "sdkVersion bundled with app, dynamiteVersion"

    .line 269
    .line 270
    invoke-virtual {v0, v14, v4, v5}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 271
    .line 272
    .line 273
    iget-object v4, v12, Lvp/g1;->d:Landroid/content/Context;

    .line 274
    .line 275
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    invoke-virtual {v4}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 280
    .line 281
    .line 282
    move-result-object v14

    .line 283
    const-string v0, ""

    .line 284
    .line 285
    const/high16 v18, -0x80000000

    .line 286
    .line 287
    const-string v19, "Unknown"

    .line 288
    .line 289
    const-string v20, "unknown"

    .line 290
    .line 291
    if-nez v14, :cond_4

    .line 292
    .line 293
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 294
    .line 295
    .line 296
    iget-object v6, v13, Lvp/p0;->j:Lvp/n0;

    .line 297
    .line 298
    move-object/from16 v22, v2

    .line 299
    .line 300
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    move-object/from16 v23, v15

    .line 305
    .line 306
    const-string v15, "PackageManager is null, app identity information might be inaccurate. appId"

    .line 307
    .line 308
    invoke-virtual {v6, v2, v15}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    :cond_3
    move-object/from16 v24, v14

    .line 312
    .line 313
    move/from16 v2, v18

    .line 314
    .line 315
    move-object/from16 v6, v19

    .line 316
    .line 317
    move-object v15, v6

    .line 318
    :goto_1
    move-object/from16 v14, v20

    .line 319
    .line 320
    goto/16 :goto_7

    .line 321
    .line 322
    :cond_4
    move-object/from16 v22, v2

    .line 323
    .line 324
    move-object/from16 v23, v15

    .line 325
    .line 326
    :try_start_0
    invoke-virtual {v14, v5}, Landroid/content/pm/PackageManager;->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v20
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 330
    :goto_2
    move-object/from16 v2, v20

    .line 331
    .line 332
    goto :goto_3

    .line 333
    :catch_0
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 334
    .line 335
    .line 336
    iget-object v2, v13, Lvp/p0;->j:Lvp/n0;

    .line 337
    .line 338
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 339
    .line 340
    .line 341
    move-result-object v6

    .line 342
    const-string v15, "Error retrieving app installer package name. appId"

    .line 343
    .line 344
    invoke-virtual {v2, v6, v15}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    goto :goto_2

    .line 348
    :goto_3
    if-nez v2, :cond_6

    .line 349
    .line 350
    const-string v2, "manual_install"

    .line 351
    .line 352
    :cond_5
    move-object/from16 v20, v2

    .line 353
    .line 354
    goto :goto_4

    .line 355
    :cond_6
    const-string v6, "com.android.vending"

    .line 356
    .line 357
    invoke-virtual {v6, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 358
    .line 359
    .line 360
    move-result v6

    .line 361
    if-eqz v6, :cond_5

    .line 362
    .line 363
    move-object/from16 v20, v0

    .line 364
    .line 365
    :goto_4
    :try_start_1
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v2

    .line 369
    const/4 v6, 0x0

    .line 370
    invoke-virtual {v14, v2, v6}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 371
    .line 372
    .line 373
    move-result-object v2

    .line 374
    if-eqz v2, :cond_3

    .line 375
    .line 376
    iget-object v6, v2, Landroid/content/pm/PackageInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 377
    .line 378
    invoke-virtual {v14, v6}, Landroid/content/pm/PackageManager;->getApplicationLabel(Landroid/content/pm/ApplicationInfo;)Ljava/lang/CharSequence;

    .line 379
    .line 380
    .line 381
    move-result-object v6

    .line 382
    invoke-static {v6}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 383
    .line 384
    .line 385
    move-result v15

    .line 386
    if-nez v15, :cond_7

    .line 387
    .line 388
    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object v6
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_2

    .line 392
    goto :goto_5

    .line 393
    :cond_7
    move-object/from16 v6, v19

    .line 394
    .line 395
    :goto_5
    :try_start_2
    iget-object v15, v2, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_3

    .line 396
    .line 397
    :try_start_3
    iget v2, v2, Landroid/content/pm/PackageInfo;->versionCode:I
    :try_end_3
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_3 .. :try_end_3} :catch_1

    .line 398
    .line 399
    move-object/from16 v24, v14

    .line 400
    .line 401
    goto :goto_1

    .line 402
    :catch_1
    move-object/from16 v19, v15

    .line 403
    .line 404
    goto :goto_6

    .line 405
    :catch_2
    move-object/from16 v6, v19

    .line 406
    .line 407
    :catch_3
    :goto_6
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 408
    .line 409
    .line 410
    iget-object v2, v13, Lvp/p0;->j:Lvp/n0;

    .line 411
    .line 412
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 413
    .line 414
    .line 415
    move-result-object v15

    .line 416
    move-object/from16 v24, v14

    .line 417
    .line 418
    const-string v14, "Error retrieving package info. appId, appName"

    .line 419
    .line 420
    invoke-virtual {v2, v15, v6, v14}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    move/from16 v2, v18

    .line 424
    .line 425
    move-object/from16 v15, v19

    .line 426
    .line 427
    goto :goto_1

    .line 428
    :goto_7
    iput-object v5, v7, Lvp/h0;->g:Ljava/lang/String;

    .line 429
    .line 430
    iput-object v14, v7, Lvp/h0;->j:Ljava/lang/String;

    .line 431
    .line 432
    iput-object v15, v7, Lvp/h0;->h:Ljava/lang/String;

    .line 433
    .line 434
    iput v2, v7, Lvp/h0;->i:I

    .line 435
    .line 436
    iput-object v6, v7, Lvp/h0;->k:Ljava/lang/String;

    .line 437
    .line 438
    const-wide/16 v14, 0x0

    .line 439
    .line 440
    iput-wide v14, v7, Lvp/h0;->l:J

    .line 441
    .line 442
    invoke-virtual {v12}, Lvp/g1;->b()I

    .line 443
    .line 444
    .line 445
    move-result v2

    .line 446
    if-eqz v2, :cond_e

    .line 447
    .line 448
    const/4 v6, 0x1

    .line 449
    if-eq v2, v6, :cond_d

    .line 450
    .line 451
    const/4 v6, 0x3

    .line 452
    if-eq v2, v6, :cond_c

    .line 453
    .line 454
    const/4 v6, 0x4

    .line 455
    if-eq v2, v6, :cond_b

    .line 456
    .line 457
    const/4 v6, 0x6

    .line 458
    if-eq v2, v6, :cond_a

    .line 459
    .line 460
    const/4 v6, 0x7

    .line 461
    if-eq v2, v6, :cond_9

    .line 462
    .line 463
    const/16 v6, 0x8

    .line 464
    .line 465
    if-eq v2, v6, :cond_8

    .line 466
    .line 467
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 468
    .line 469
    .line 470
    iget-object v6, v13, Lvp/p0;->p:Lvp/n0;

    .line 471
    .line 472
    const-string v14, "App measurement disabled"

    .line 473
    .line 474
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 475
    .line 476
    .line 477
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 478
    .line 479
    .line 480
    iget-object v6, v13, Lvp/p0;->k:Lvp/n0;

    .line 481
    .line 482
    const-string v14, "Invalid scion state in identity"

    .line 483
    .line 484
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    goto :goto_8

    .line 488
    :cond_8
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 489
    .line 490
    .line 491
    iget-object v6, v13, Lvp/p0;->p:Lvp/n0;

    .line 492
    .line 493
    const-string v14, "App measurement disabled due to denied storage consent"

    .line 494
    .line 495
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 496
    .line 497
    .line 498
    goto :goto_8

    .line 499
    :cond_9
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 500
    .line 501
    .line 502
    iget-object v6, v13, Lvp/p0;->p:Lvp/n0;

    .line 503
    .line 504
    const-string v14, "App measurement disabled via the global data collection setting"

    .line 505
    .line 506
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    goto :goto_8

    .line 510
    :cond_a
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 511
    .line 512
    .line 513
    iget-object v6, v13, Lvp/p0;->o:Lvp/n0;

    .line 514
    .line 515
    const-string v14, "App measurement deactivated via resources. This method is being deprecated. Please refer to https://firebase.google.com/support/guides/disable-analytics"

    .line 516
    .line 517
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    goto :goto_8

    .line 521
    :cond_b
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 522
    .line 523
    .line 524
    iget-object v6, v13, Lvp/p0;->p:Lvp/n0;

    .line 525
    .line 526
    const-string v14, "App measurement disabled via the manifest"

    .line 527
    .line 528
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 529
    .line 530
    .line 531
    goto :goto_8

    .line 532
    :cond_c
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 533
    .line 534
    .line 535
    iget-object v6, v13, Lvp/p0;->p:Lvp/n0;

    .line 536
    .line 537
    const-string v14, "App measurement disabled by setAnalyticsCollectionEnabled(false)"

    .line 538
    .line 539
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    goto :goto_8

    .line 543
    :cond_d
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 544
    .line 545
    .line 546
    iget-object v6, v13, Lvp/p0;->p:Lvp/n0;

    .line 547
    .line 548
    const-string v14, "App measurement deactivated via the manifest"

    .line 549
    .line 550
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    goto :goto_8

    .line 554
    :cond_e
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 555
    .line 556
    .line 557
    iget-object v6, v13, Lvp/p0;->r:Lvp/n0;

    .line 558
    .line 559
    const-string v14, "App measurement collection enabled"

    .line 560
    .line 561
    invoke-virtual {v6, v14}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    :goto_8
    iput-object v0, v7, Lvp/h0;->r:Ljava/lang/String;

    .line 565
    .line 566
    :try_start_4
    iget-object v6, v12, Lvp/g1;->s:Ljava/lang/String;

    .line 567
    .line 568
    invoke-static {v4, v6}, Lvp/t1;->b(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    .line 569
    .line 570
    .line 571
    move-result-object v6

    .line 572
    invoke-static {v6}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 573
    .line 574
    .line 575
    move-result v14

    .line 576
    if-eqz v14, :cond_f

    .line 577
    .line 578
    goto :goto_9

    .line 579
    :cond_f
    move-object v0, v6

    .line 580
    :goto_9
    iput-object v0, v7, Lvp/h0;->r:Ljava/lang/String;

    .line 581
    .line 582
    if-nez v2, :cond_10

    .line 583
    .line 584
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 585
    .line 586
    .line 587
    iget-object v0, v13, Lvp/p0;->r:Lvp/n0;

    .line 588
    .line 589
    const-string v2, "App measurement enabled for app package, google app id"

    .line 590
    .line 591
    iget-object v6, v7, Lvp/h0;->g:Ljava/lang/String;

    .line 592
    .line 593
    iget-object v14, v7, Lvp/h0;->r:Ljava/lang/String;

    .line 594
    .line 595
    invoke-virtual {v0, v6, v14, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_4
    .catch Ljava/lang/IllegalStateException; {:try_start_4 .. :try_end_4} :catch_4

    .line 596
    .line 597
    .line 598
    goto :goto_a

    .line 599
    :catch_4
    move-exception v0

    .line 600
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 601
    .line 602
    .line 603
    iget-object v2, v13, Lvp/p0;->j:Lvp/n0;

    .line 604
    .line 605
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 606
    .line 607
    .line 608
    move-result-object v5

    .line 609
    const-string v6, "Fetching Google App Id failed with exception. appId"

    .line 610
    .line 611
    invoke-virtual {v2, v5, v0, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 612
    .line 613
    .line 614
    :cond_10
    :goto_a
    const/4 v2, 0x0

    .line 615
    iput-object v2, v7, Lvp/h0;->o:Ljava/util/List;

    .line 616
    .line 617
    iget-object v0, v12, Lvp/g1;->g:Lvp/h;

    .line 618
    .line 619
    iget-object v5, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 620
    .line 621
    check-cast v5, Lvp/g1;

    .line 622
    .line 623
    const-string v6, "analytics.safelisted_events"

    .line 624
    .line 625
    invoke-static {v6}, Lno/c0;->e(Ljava/lang/String;)V

    .line 626
    .line 627
    .line 628
    invoke-virtual {v0}, Lvp/h;->l0()Landroid/os/Bundle;

    .line 629
    .line 630
    .line 631
    move-result-object v0

    .line 632
    if-nez v0, :cond_11

    .line 633
    .line 634
    iget-object v0, v5, Lvp/g1;->i:Lvp/p0;

    .line 635
    .line 636
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 637
    .line 638
    .line 639
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 640
    .line 641
    const-string v6, "Failed to load metadata: Metadata bundle is null"

    .line 642
    .line 643
    invoke-virtual {v0, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 644
    .line 645
    .line 646
    :goto_b
    move-object v0, v2

    .line 647
    goto :goto_c

    .line 648
    :cond_11
    invoke-virtual {v0, v6}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 649
    .line 650
    .line 651
    move-result v14

    .line 652
    if-nez v14, :cond_12

    .line 653
    .line 654
    goto :goto_b

    .line 655
    :cond_12
    invoke-virtual {v0, v6}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 656
    .line 657
    .line 658
    move-result v0

    .line 659
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 660
    .line 661
    .line 662
    move-result-object v0

    .line 663
    :goto_c
    if-eqz v0, :cond_14

    .line 664
    .line 665
    :try_start_5
    iget-object v6, v5, Lvp/g1;->d:Landroid/content/Context;

    .line 666
    .line 667
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 668
    .line 669
    .line 670
    move-result-object v6

    .line 671
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 672
    .line 673
    .line 674
    move-result v0

    .line 675
    invoke-virtual {v6, v0}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 676
    .line 677
    .line 678
    move-result-object v0

    .line 679
    if-nez v0, :cond_13

    .line 680
    .line 681
    goto :goto_d

    .line 682
    :cond_13
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 683
    .line 684
    .line 685
    move-result-object v2
    :try_end_5
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_5 .. :try_end_5} :catch_5

    .line 686
    goto :goto_d

    .line 687
    :catch_5
    move-exception v0

    .line 688
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 689
    .line 690
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 691
    .line 692
    .line 693
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 694
    .line 695
    const-string v6, "Failed to load string array from metadata: resource not found"

    .line 696
    .line 697
    invoke-virtual {v5, v0, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 698
    .line 699
    .line 700
    :cond_14
    :goto_d
    if-nez v2, :cond_15

    .line 701
    .line 702
    goto :goto_e

    .line 703
    :cond_15
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 704
    .line 705
    .line 706
    move-result v0

    .line 707
    if-eqz v0, :cond_16

    .line 708
    .line 709
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 710
    .line 711
    .line 712
    iget-object v0, v13, Lvp/p0;->o:Lvp/n0;

    .line 713
    .line 714
    const-string v2, "Safelisted event list is empty. Ignoring"

    .line 715
    .line 716
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    goto :goto_f

    .line 720
    :cond_16
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 721
    .line 722
    .line 723
    move-result-object v0

    .line 724
    :cond_17
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 725
    .line 726
    .line 727
    move-result v5

    .line 728
    if-eqz v5, :cond_18

    .line 729
    .line 730
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v5

    .line 734
    check-cast v5, Ljava/lang/String;

    .line 735
    .line 736
    iget-object v6, v12, Lvp/g1;->l:Lvp/d4;

    .line 737
    .line 738
    invoke-static {v6}, Lvp/g1;->g(Lap0/o;)V

    .line 739
    .line 740
    .line 741
    const-string v13, "safelisted event"

    .line 742
    .line 743
    invoke-virtual {v6, v13, v5}, Lvp/d4;->b1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 744
    .line 745
    .line 746
    move-result v5

    .line 747
    if-nez v5, :cond_17

    .line 748
    .line 749
    goto :goto_f

    .line 750
    :cond_18
    :goto_e
    iput-object v2, v7, Lvp/h0;->o:Ljava/util/List;

    .line 751
    .line 752
    :goto_f
    if-eqz v24, :cond_19

    .line 753
    .line 754
    invoke-static {v4}, Lvo/a;->f(Landroid/content/Context;)Z

    .line 755
    .line 756
    .line 757
    move-result v0

    .line 758
    iput v0, v7, Lvp/h0;->q:I

    .line 759
    .line 760
    goto :goto_10

    .line 761
    :cond_19
    const/4 v6, 0x0

    .line 762
    iput v6, v7, Lvp/h0;->q:I

    .line 763
    .line 764
    :goto_10
    iget-object v0, v7, Lap0/o;->e:Ljava/lang/Object;

    .line 765
    .line 766
    check-cast v0, Lvp/g1;

    .line 767
    .line 768
    iget-object v0, v0, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 769
    .line 770
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 771
    .line 772
    .line 773
    const/4 v2, 0x1

    .line 774
    iput-boolean v2, v7, Lvp/b0;->f:Z

    .line 775
    .line 776
    new-instance v0, Lvp/o2;

    .line 777
    .line 778
    invoke-direct {v0, v3}, Lvp/b0;-><init>(Lvp/g1;)V

    .line 779
    .line 780
    .line 781
    invoke-virtual {v0}, Lvp/b0;->c0()V

    .line 782
    .line 783
    .line 784
    iput-object v0, v3, Lvp/g1;->x:Lvp/o2;

    .line 785
    .line 786
    iget-boolean v2, v0, Lvp/b0;->f:Z

    .line 787
    .line 788
    if-nez v2, :cond_45

    .line 789
    .line 790
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 791
    .line 792
    check-cast v2, Lvp/g1;

    .line 793
    .line 794
    iget-object v2, v2, Lvp/g1;->d:Landroid/content/Context;

    .line 795
    .line 796
    const-string v4, "jobscheduler"

    .line 797
    .line 798
    invoke-virtual {v2, v4}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 799
    .line 800
    .line 801
    move-result-object v2

    .line 802
    check-cast v2, Landroid/app/job/JobScheduler;

    .line 803
    .line 804
    iput-object v2, v0, Lvp/o2;->g:Landroid/app/job/JobScheduler;

    .line 805
    .line 806
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 807
    .line 808
    check-cast v2, Lvp/g1;

    .line 809
    .line 810
    iget-object v2, v2, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 811
    .line 812
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 813
    .line 814
    .line 815
    const/4 v2, 0x1

    .line 816
    iput-boolean v2, v0, Lvp/b0;->f:Z

    .line 817
    .line 818
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 819
    .line 820
    .line 821
    iget-object v0, v8, Lvp/p0;->q:Lvp/n0;

    .line 822
    .line 823
    iget-object v2, v8, Lvp/p0;->p:Lvp/n0;

    .line 824
    .line 825
    iget-object v4, v8, Lvp/p0;->r:Lvp/n0;

    .line 826
    .line 827
    iget-object v5, v8, Lvp/p0;->j:Lvp/n0;

    .line 828
    .line 829
    invoke-virtual {v1}, Lvp/h;->f0()V

    .line 830
    .line 831
    .line 832
    const-wide/32 v6, 0x2078d

    .line 833
    .line 834
    .line 835
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 836
    .line 837
    .line 838
    move-result-object v6

    .line 839
    const-string v7, "App measurement initialized, version"

    .line 840
    .line 841
    invoke-virtual {v2, v6, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 842
    .line 843
    .line 844
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 845
    .line 846
    .line 847
    const-string v6, "To enable debug logging run: adb shell setprop log.tag.FA VERBOSE"

    .line 848
    .line 849
    invoke-virtual {v2, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 850
    .line 851
    .line 852
    invoke-virtual/range {v22 .. v22}, Lvp/h0;->g0()Ljava/lang/String;

    .line 853
    .line 854
    .line 855
    move-result-object v6

    .line 856
    iget-object v7, v1, Lvp/h;->g:Ljava/lang/String;

    .line 857
    .line 858
    invoke-virtual {v10, v6, v7}, Lvp/d4;->A0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 859
    .line 860
    .line 861
    move-result v7

    .line 862
    if-eqz v7, :cond_1a

    .line 863
    .line 864
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 865
    .line 866
    .line 867
    const-string v6, "Faster debug mode event logging enabled. To disable, run:\n  adb shell setprop debug.firebase.analytics.app .none."

    .line 868
    .line 869
    invoke-virtual {v2, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 870
    .line 871
    .line 872
    goto :goto_11

    .line 873
    :cond_1a
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 874
    .line 875
    .line 876
    invoke-static {v6}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 877
    .line 878
    .line 879
    move-result-object v6

    .line 880
    const-string v7, "To enable faster debug mode event logging run:\n  adb shell setprop debug.firebase.analytics.app "

    .line 881
    .line 882
    invoke-virtual {v7, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 883
    .line 884
    .line 885
    move-result-object v6

    .line 886
    invoke-virtual {v2, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 887
    .line 888
    .line 889
    :goto_11
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 890
    .line 891
    .line 892
    const-string v6, "Debug-level message logging enabled"

    .line 893
    .line 894
    invoke-virtual {v0, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 895
    .line 896
    .line 897
    iget v6, v3, Lvp/g1;->D:I

    .line 898
    .line 899
    iget-object v7, v3, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 900
    .line 901
    invoke-virtual {v7}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 902
    .line 903
    .line 904
    move-result v12

    .line 905
    if-eq v6, v12, :cond_1b

    .line 906
    .line 907
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 908
    .line 909
    .line 910
    iget v6, v3, Lvp/g1;->D:I

    .line 911
    .line 912
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 913
    .line 914
    .line 915
    move-result-object v6

    .line 916
    invoke-virtual {v7}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 917
    .line 918
    .line 919
    move-result v7

    .line 920
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 921
    .line 922
    .line 923
    move-result-object v7

    .line 924
    const-string v12, "Not all components initialized"

    .line 925
    .line 926
    invoke-virtual {v5, v6, v7, v12}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 927
    .line 928
    .line 929
    :cond_1b
    const/4 v6, 0x1

    .line 930
    iput-boolean v6, v3, Lvp/g1;->y:Z

    .line 931
    .line 932
    iget-wide v6, v3, Lvp/g1;->G:J

    .line 933
    .line 934
    iget-object v12, v3, Lvp/g1;->p:Lvp/j2;

    .line 935
    .line 936
    iget-object v13, v3, Lvp/g1;->j:Lvp/e1;

    .line 937
    .line 938
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 939
    .line 940
    .line 941
    invoke-virtual {v13}, Lvp/e1;->a0()V

    .line 942
    .line 943
    .line 944
    iget-object v13, v3, Lvp/g1;->x:Lvp/o2;

    .line 945
    .line 946
    invoke-static {v13}, Lvp/g1;->e(Lvp/x;)V

    .line 947
    .line 948
    .line 949
    iget-object v13, v3, Lvp/g1;->x:Lvp/o2;

    .line 950
    .line 951
    invoke-virtual {v13}, Lvp/o2;->f0()I

    .line 952
    .line 953
    .line 954
    move-result v13

    .line 955
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 956
    .line 957
    .line 958
    sget-object v14, Lvp/z;->Q0:Lvp/y;

    .line 959
    .line 960
    const/4 v15, 0x0

    .line 961
    invoke-virtual {v1, v15, v14}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 962
    .line 963
    .line 964
    move-result v14

    .line 965
    const/4 v15, 0x2

    .line 966
    move/from16 v19, v14

    .line 967
    .line 968
    if-ne v13, v15, :cond_1c

    .line 969
    .line 970
    const/4 v13, 0x1

    .line 971
    goto :goto_12

    .line 972
    :cond_1c
    const/4 v13, 0x0

    .line 973
    :goto_12
    const-wide/16 v20, 0x1

    .line 974
    .line 975
    if-eqz v19, :cond_1d

    .line 976
    .line 977
    invoke-virtual {v10}, Lap0/o;->a0()V

    .line 978
    .line 979
    .line 980
    invoke-virtual {v10}, Lvp/d4;->v0()J

    .line 981
    .line 982
    .line 983
    move-result-wide v22

    .line 984
    cmp-long v19, v22, v20

    .line 985
    .line 986
    if-nez v19, :cond_1d

    .line 987
    .line 988
    goto :goto_13

    .line 989
    :cond_1d
    if-eqz v13, :cond_1e

    .line 990
    .line 991
    const/4 v13, 0x1

    .line 992
    :goto_13
    invoke-virtual {v10}, Lap0/o;->a0()V

    .line 993
    .line 994
    .line 995
    new-instance v14, Landroid/content/IntentFilter;

    .line 996
    .line 997
    invoke-direct {v14}, Landroid/content/IntentFilter;-><init>()V

    .line 998
    .line 999
    .line 1000
    const-string v15, "com.google.android.gms.measurement.TRIGGERS_AVAILABLE"

    .line 1001
    .line 1002
    invoke-virtual {v14, v15}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 1003
    .line 1004
    .line 1005
    const-string v15, "com.google.android.gms.measurement.BATCHES_AVAILABLE"

    .line 1006
    .line 1007
    invoke-virtual {v14, v15}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 1008
    .line 1009
    .line 1010
    new-instance v15, Lc8/e;

    .line 1011
    .line 1012
    move/from16 v23, v13

    .line 1013
    .line 1014
    move-object/from16 v13, p0

    .line 1015
    .line 1016
    invoke-direct {v15, v13}, Lc8/e;-><init>(Lvp/g1;)V

    .line 1017
    .line 1018
    .line 1019
    move-object/from16 v24, v8

    .line 1020
    .line 1021
    iget-object v8, v13, Lvp/g1;->d:Landroid/content/Context;

    .line 1022
    .line 1023
    move-object/from16 p0, v2

    .line 1024
    .line 1025
    const/4 v2, 0x2

    .line 1026
    invoke-static {v8, v15, v14, v2}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    .line 1027
    .line 1028
    .line 1029
    iget-object v2, v13, Lvp/g1;->i:Lvp/p0;

    .line 1030
    .line 1031
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 1032
    .line 1033
    .line 1034
    iget-object v2, v2, Lvp/p0;->q:Lvp/n0;

    .line 1035
    .line 1036
    const-string v8, "Registered app receiver"

    .line 1037
    .line 1038
    invoke-virtual {v2, v8}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1039
    .line 1040
    .line 1041
    if-eqz v23, :cond_1f

    .line 1042
    .line 1043
    iget-object v2, v3, Lvp/g1;->x:Lvp/o2;

    .line 1044
    .line 1045
    invoke-static {v2}, Lvp/g1;->e(Lvp/x;)V

    .line 1046
    .line 1047
    .line 1048
    iget-object v2, v3, Lvp/g1;->x:Lvp/o2;

    .line 1049
    .line 1050
    sget-object v8, Lvp/z;->C:Lvp/y;

    .line 1051
    .line 1052
    const/4 v14, 0x0

    .line 1053
    invoke-virtual {v8, v14}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v8

    .line 1057
    check-cast v8, Ljava/lang/Long;

    .line 1058
    .line 1059
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 1060
    .line 1061
    .line 1062
    move-result-wide v14

    .line 1063
    invoke-virtual {v2, v14, v15}, Lvp/o2;->e0(J)V

    .line 1064
    .line 1065
    .line 1066
    goto :goto_14

    .line 1067
    :cond_1e
    move-object/from16 v13, p0

    .line 1068
    .line 1069
    move-object/from16 p0, v2

    .line 1070
    .line 1071
    move-object/from16 v24, v8

    .line 1072
    .line 1073
    :cond_1f
    :goto_14
    iget-object v2, v9, Lvp/w0;->k:La8/b;

    .line 1074
    .line 1075
    invoke-virtual {v9}, Lvp/w0;->h0()Lvp/s1;

    .line 1076
    .line 1077
    .line 1078
    move-result-object v8

    .line 1079
    iget v14, v8, Lvp/s1;->b:I

    .line 1080
    .line 1081
    const-string v15, "google_analytics_default_allow_ad_storage"

    .line 1082
    .line 1083
    move-object/from16 v22, v8

    .line 1084
    .line 1085
    const/4 v8, 0x0

    .line 1086
    invoke-virtual {v1, v15, v8}, Lvp/h;->p0(Ljava/lang/String;Z)Lvp/p1;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v15

    .line 1090
    move-object/from16 v23, v13

    .line 1091
    .line 1092
    const-string v13, "google_analytics_default_allow_analytics_storage"

    .line 1093
    .line 1094
    invoke-virtual {v1, v13, v8}, Lvp/h;->p0(Ljava/lang/String;Z)Lvp/p1;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v13

    .line 1098
    sget-object v8, Lvp/p1;->e:Lvp/p1;

    .line 1099
    .line 1100
    move-object/from16 v25, v2

    .line 1101
    .line 1102
    sget-object v2, Lvp/r1;->f:Lvp/r1;

    .line 1103
    .line 1104
    move-object/from16 v26, v3

    .line 1105
    .line 1106
    const-class v3, Lvp/r1;

    .line 1107
    .line 1108
    move-object/from16 v27, v5

    .line 1109
    .line 1110
    if-ne v15, v8, :cond_21

    .line 1111
    .line 1112
    if-eq v13, v8, :cond_20

    .line 1113
    .line 1114
    goto :goto_15

    .line 1115
    :cond_20
    move-wide/from16 v29, v6

    .line 1116
    .line 1117
    move-object/from16 v28, v10

    .line 1118
    .line 1119
    goto :goto_16

    .line 1120
    :cond_21
    :goto_15
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v5

    .line 1124
    move-object/from16 v28, v10

    .line 1125
    .line 1126
    const-string v10, "consent_source"

    .line 1127
    .line 1128
    move-wide/from16 v29, v6

    .line 1129
    .line 1130
    const/16 v6, 0x64

    .line 1131
    .line 1132
    invoke-interface {v5, v10, v6}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 1133
    .line 1134
    .line 1135
    move-result v5

    .line 1136
    const/16 v6, -0xa

    .line 1137
    .line 1138
    invoke-static {v6, v5}, Lvp/s1;->l(II)Z

    .line 1139
    .line 1140
    .line 1141
    move-result v5

    .line 1142
    if-eqz v5, :cond_22

    .line 1143
    .line 1144
    new-instance v5, Ljava/util/EnumMap;

    .line 1145
    .line 1146
    invoke-direct {v5, v3}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    .line 1147
    .line 1148
    .line 1149
    sget-object v7, Lvp/r1;->e:Lvp/r1;

    .line 1150
    .line 1151
    invoke-virtual {v5, v7, v15}, Ljava/util/EnumMap;->put(Ljava/lang/Enum;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1152
    .line 1153
    .line 1154
    invoke-virtual {v5, v2, v13}, Ljava/util/EnumMap;->put(Ljava/lang/Enum;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1155
    .line 1156
    .line 1157
    new-instance v7, Lvp/s1;

    .line 1158
    .line 1159
    invoke-direct {v7, v5, v6}, Lvp/s1;-><init>(Ljava/util/EnumMap;I)V

    .line 1160
    .line 1161
    .line 1162
    const/4 v6, 0x0

    .line 1163
    goto :goto_19

    .line 1164
    :cond_22
    :goto_16
    invoke-virtual/range {v26 .. v26}, Lvp/g1;->q()Lvp/h0;

    .line 1165
    .line 1166
    .line 1167
    move-result-object v5

    .line 1168
    invoke-virtual {v5}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v5

    .line 1172
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1173
    .line 1174
    .line 1175
    move-result v5

    .line 1176
    if-nez v5, :cond_23

    .line 1177
    .line 1178
    if-eqz v14, :cond_24

    .line 1179
    .line 1180
    const/16 v5, 0x1e

    .line 1181
    .line 1182
    if-eq v14, v5, :cond_24

    .line 1183
    .line 1184
    const/16 v5, 0xa

    .line 1185
    .line 1186
    if-eq v14, v5, :cond_24

    .line 1187
    .line 1188
    const/16 v5, 0x28

    .line 1189
    .line 1190
    if-ne v14, v5, :cond_23

    .line 1191
    .line 1192
    goto :goto_18

    .line 1193
    :cond_23
    const/4 v6, 0x0

    .line 1194
    :goto_17
    const/4 v7, 0x0

    .line 1195
    goto :goto_19

    .line 1196
    :cond_24
    :goto_18
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1197
    .line 1198
    .line 1199
    new-instance v5, Lvp/s1;

    .line 1200
    .line 1201
    const/16 v6, -0xa

    .line 1202
    .line 1203
    invoke-direct {v5, v6}, Lvp/s1;-><init>(I)V

    .line 1204
    .line 1205
    .line 1206
    const/4 v6, 0x0

    .line 1207
    invoke-virtual {v12, v5, v6}, Lvp/j2;->w0(Lvp/s1;Z)V

    .line 1208
    .line 1209
    .line 1210
    goto :goto_17

    .line 1211
    :goto_19
    if-eqz v7, :cond_25

    .line 1212
    .line 1213
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1214
    .line 1215
    .line 1216
    const/4 v5, 0x1

    .line 1217
    invoke-virtual {v12, v7, v5}, Lvp/j2;->w0(Lvp/s1;Z)V

    .line 1218
    .line 1219
    .line 1220
    goto :goto_1a

    .line 1221
    :cond_25
    move-object/from16 v7, v22

    .line 1222
    .line 1223
    :goto_1a
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1224
    .line 1225
    .line 1226
    iget-object v5, v12, Lap0/o;->e:Ljava/lang/Object;

    .line 1227
    .line 1228
    check-cast v5, Lvp/g1;

    .line 1229
    .line 1230
    invoke-virtual {v12, v7}, Lvp/j2;->e0(Lvp/s1;)V

    .line 1231
    .line 1232
    .line 1233
    invoke-virtual {v9}, Lap0/o;->a0()V

    .line 1234
    .line 1235
    .line 1236
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1237
    .line 1238
    .line 1239
    move-result-object v7

    .line 1240
    const-string v10, "dma_consent_settings"

    .line 1241
    .line 1242
    const/4 v14, 0x0

    .line 1243
    invoke-interface {v7, v10, v14}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1244
    .line 1245
    .line 1246
    move-result-object v7

    .line 1247
    invoke-static {v7}, Lvp/p;->b(Ljava/lang/String;)Lvp/p;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v7

    .line 1251
    iget v7, v7, Lvp/p;->a:I

    .line 1252
    .line 1253
    const-string v10, "google_analytics_default_allow_ad_personalization_signals"

    .line 1254
    .line 1255
    const/4 v13, 0x1

    .line 1256
    invoke-virtual {v1, v10, v13}, Lvp/h;->p0(Ljava/lang/String;Z)Lvp/p1;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v10

    .line 1260
    if-eq v10, v8, :cond_26

    .line 1261
    .line 1262
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1263
    .line 1264
    .line 1265
    const-string v14, "Default ad personalization consent from Manifest"

    .line 1266
    .line 1267
    invoke-virtual {v4, v10, v14}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1268
    .line 1269
    .line 1270
    :cond_26
    const-string v10, "google_analytics_default_allow_ad_user_data"

    .line 1271
    .line 1272
    invoke-virtual {v1, v10, v13}, Lvp/h;->p0(Ljava/lang/String;Z)Lvp/p1;

    .line 1273
    .line 1274
    .line 1275
    move-result-object v10

    .line 1276
    if-eq v10, v8, :cond_27

    .line 1277
    .line 1278
    const/16 v14, -0xa

    .line 1279
    .line 1280
    invoke-static {v14, v7}, Lvp/s1;->l(II)Z

    .line 1281
    .line 1282
    .line 1283
    move-result v15

    .line 1284
    if-eqz v15, :cond_27

    .line 1285
    .line 1286
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1287
    .line 1288
    .line 1289
    new-instance v7, Ljava/util/EnumMap;

    .line 1290
    .line 1291
    invoke-direct {v7, v3}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    .line 1292
    .line 1293
    .line 1294
    sget-object v3, Lvp/r1;->g:Lvp/r1;

    .line 1295
    .line 1296
    invoke-virtual {v7, v3, v10}, Ljava/util/EnumMap;->put(Ljava/lang/Enum;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1297
    .line 1298
    .line 1299
    new-instance v3, Lvp/p;

    .line 1300
    .line 1301
    const/4 v8, 0x0

    .line 1302
    invoke-direct {v3, v7, v14, v8, v8}, Lvp/p;-><init>(Ljava/util/EnumMap;ILjava/lang/Boolean;Ljava/lang/String;)V

    .line 1303
    .line 1304
    .line 1305
    invoke-virtual {v12, v3, v13}, Lvp/j2;->v0(Lvp/p;Z)V

    .line 1306
    .line 1307
    .line 1308
    goto :goto_1b

    .line 1309
    :cond_27
    invoke-virtual/range {v26 .. v26}, Lvp/g1;->q()Lvp/h0;

    .line 1310
    .line 1311
    .line 1312
    move-result-object v3

    .line 1313
    invoke-virtual {v3}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1314
    .line 1315
    .line 1316
    move-result-object v3

    .line 1317
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1318
    .line 1319
    .line 1320
    move-result v3

    .line 1321
    if-nez v3, :cond_29

    .line 1322
    .line 1323
    if-eqz v7, :cond_28

    .line 1324
    .line 1325
    const/16 v3, 0x1e

    .line 1326
    .line 1327
    if-ne v7, v3, :cond_29

    .line 1328
    .line 1329
    :cond_28
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1330
    .line 1331
    .line 1332
    new-instance v3, Lvp/p;

    .line 1333
    .line 1334
    const/16 v7, -0xa

    .line 1335
    .line 1336
    const/4 v14, 0x0

    .line 1337
    invoke-direct {v3, v14, v7, v14, v14}, Lvp/p;-><init>(Ljava/lang/Boolean;ILjava/lang/Boolean;Ljava/lang/String;)V

    .line 1338
    .line 1339
    .line 1340
    const/4 v13, 0x1

    .line 1341
    invoke-virtual {v12, v3, v13}, Lvp/j2;->v0(Lvp/p;Z)V

    .line 1342
    .line 1343
    .line 1344
    goto :goto_1b

    .line 1345
    :cond_29
    invoke-virtual/range {v26 .. v26}, Lvp/g1;->q()Lvp/h0;

    .line 1346
    .line 1347
    .line 1348
    move-result-object v3

    .line 1349
    invoke-virtual {v3}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v3

    .line 1353
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1354
    .line 1355
    .line 1356
    move-result v3

    .line 1357
    if-eqz v3, :cond_2b

    .line 1358
    .line 1359
    if-eqz v11, :cond_2b

    .line 1360
    .line 1361
    iget-object v3, v11, Lcom/google/android/gms/internal/measurement/u0;->g:Landroid/os/Bundle;

    .line 1362
    .line 1363
    if-eqz v3, :cond_2b

    .line 1364
    .line 1365
    const/16 v10, 0x1e

    .line 1366
    .line 1367
    invoke-static {v10, v7}, Lvp/s1;->l(II)Z

    .line 1368
    .line 1369
    .line 1370
    move-result v7

    .line 1371
    if-eqz v7, :cond_2b

    .line 1372
    .line 1373
    invoke-static {v10, v3}, Lvp/p;->c(ILandroid/os/Bundle;)Lvp/p;

    .line 1374
    .line 1375
    .line 1376
    move-result-object v3

    .line 1377
    iget-object v7, v3, Lvp/p;->e:Ljava/util/EnumMap;

    .line 1378
    .line 1379
    invoke-virtual {v7}, Ljava/util/EnumMap;->values()Ljava/util/Collection;

    .line 1380
    .line 1381
    .line 1382
    move-result-object v7

    .line 1383
    invoke-interface {v7}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 1384
    .line 1385
    .line 1386
    move-result-object v7

    .line 1387
    :cond_2a
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1388
    .line 1389
    .line 1390
    move-result v10

    .line 1391
    if-eqz v10, :cond_2b

    .line 1392
    .line 1393
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1394
    .line 1395
    .line 1396
    move-result-object v10

    .line 1397
    check-cast v10, Lvp/p1;

    .line 1398
    .line 1399
    if-eq v10, v8, :cond_2a

    .line 1400
    .line 1401
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1402
    .line 1403
    .line 1404
    const/4 v13, 0x1

    .line 1405
    invoke-virtual {v12, v3, v13}, Lvp/j2;->v0(Lvp/p;Z)V

    .line 1406
    .line 1407
    .line 1408
    :cond_2b
    :goto_1b
    const-string v3, "google_analytics_tcf_data_enabled"

    .line 1409
    .line 1410
    invoke-virtual {v1, v3}, Lvp/h;->m0(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 1411
    .line 1412
    .line 1413
    move-result-object v3

    .line 1414
    if-eqz v3, :cond_2c

    .line 1415
    .line 1416
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1417
    .line 1418
    .line 1419
    move-result v3

    .line 1420
    if-eqz v3, :cond_2e

    .line 1421
    .line 1422
    :cond_2c
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1423
    .line 1424
    .line 1425
    const-string v3, "TCF client enabled."

    .line 1426
    .line 1427
    invoke-virtual {v0, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1428
    .line 1429
    .line 1430
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1431
    .line 1432
    .line 1433
    invoke-virtual {v12}, Lvp/x;->a0()V

    .line 1434
    .line 1435
    .line 1436
    iget-object v0, v5, Lvp/g1;->i:Lvp/p0;

    .line 1437
    .line 1438
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 1439
    .line 1440
    .line 1441
    iget-object v0, v0, Lvp/p0;->q:Lvp/n0;

    .line 1442
    .line 1443
    const-string v3, "Register tcfPrefChangeListener."

    .line 1444
    .line 1445
    invoke-virtual {v0, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1446
    .line 1447
    .line 1448
    iget-object v0, v12, Lvp/j2;->y:Lvp/i2;

    .line 1449
    .line 1450
    if-nez v0, :cond_2d

    .line 1451
    .line 1452
    new-instance v0, Lvp/x1;

    .line 1453
    .line 1454
    const/4 v3, 0x2

    .line 1455
    invoke-direct {v0, v12, v5, v3}, Lvp/x1;-><init>(Lvp/j2;Lvp/o1;I)V

    .line 1456
    .line 1457
    .line 1458
    iput-object v0, v12, Lvp/j2;->z:Lvp/x1;

    .line 1459
    .line 1460
    new-instance v0, Lvp/i2;

    .line 1461
    .line 1462
    invoke-direct {v0, v12}, Lvp/i2;-><init>(Lvp/j2;)V

    .line 1463
    .line 1464
    .line 1465
    iput-object v0, v12, Lvp/j2;->y:Lvp/i2;

    .line 1466
    .line 1467
    :cond_2d
    iget-object v0, v5, Lvp/g1;->h:Lvp/w0;

    .line 1468
    .line 1469
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 1470
    .line 1471
    .line 1472
    invoke-virtual {v0}, Lvp/w0;->f0()Landroid/content/SharedPreferences;

    .line 1473
    .line 1474
    .line 1475
    move-result-object v0

    .line 1476
    iget-object v3, v12, Lvp/j2;->y:Lvp/i2;

    .line 1477
    .line 1478
    invoke-interface {v0, v3}, Landroid/content/SharedPreferences;->registerOnSharedPreferenceChangeListener(Landroid/content/SharedPreferences$OnSharedPreferenceChangeListener;)V

    .line 1479
    .line 1480
    .line 1481
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1482
    .line 1483
    .line 1484
    invoke-virtual {v12}, Lvp/j2;->g0()V

    .line 1485
    .line 1486
    .line 1487
    :cond_2e
    iget-object v0, v9, Lvp/w0;->j:La8/s1;

    .line 1488
    .line 1489
    invoke-virtual {v0}, La8/s1;->g()J

    .line 1490
    .line 1491
    .line 1492
    move-result-wide v7

    .line 1493
    cmp-long v3, v7, v16

    .line 1494
    .line 1495
    if-nez v3, :cond_2f

    .line 1496
    .line 1497
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1498
    .line 1499
    .line 1500
    const-string v3, "Persisting first open"

    .line 1501
    .line 1502
    invoke-static/range {v29 .. v30}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1503
    .line 1504
    .line 1505
    move-result-object v7

    .line 1506
    invoke-virtual {v4, v7, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1507
    .line 1508
    .line 1509
    move-wide/from16 v7, v29

    .line 1510
    .line 1511
    invoke-virtual {v0, v7, v8}, La8/s1;->h(J)V

    .line 1512
    .line 1513
    .line 1514
    goto :goto_1c

    .line 1515
    :cond_2f
    move-wide/from16 v7, v29

    .line 1516
    .line 1517
    :goto_1c
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1518
    .line 1519
    .line 1520
    iget-object v3, v12, Lvp/j2;->v:Lro/f;

    .line 1521
    .line 1522
    invoke-virtual {v3}, Lro/f;->v()Z

    .line 1523
    .line 1524
    .line 1525
    move-result v10

    .line 1526
    if-eqz v10, :cond_30

    .line 1527
    .line 1528
    invoke-virtual {v3}, Lro/f;->u()Z

    .line 1529
    .line 1530
    .line 1531
    move-result v10

    .line 1532
    if-eqz v10, :cond_30

    .line 1533
    .line 1534
    iget-object v3, v3, Lro/f;->e:Ljava/lang/Object;

    .line 1535
    .line 1536
    check-cast v3, Lvp/g1;

    .line 1537
    .line 1538
    iget-object v3, v3, Lvp/g1;->h:Lvp/w0;

    .line 1539
    .line 1540
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 1541
    .line 1542
    .line 1543
    iget-object v3, v3, Lvp/w0;->A:La8/b;

    .line 1544
    .line 1545
    const/4 v14, 0x0

    .line 1546
    invoke-virtual {v3, v14}, La8/b;->u(Ljava/lang/String;)V

    .line 1547
    .line 1548
    .line 1549
    :cond_30
    invoke-virtual/range {v26 .. v26}, Lvp/g1;->c()Z

    .line 1550
    .line 1551
    .line 1552
    move-result v3

    .line 1553
    if-nez v3, :cond_36

    .line 1554
    .line 1555
    invoke-virtual/range {v26 .. v26}, Lvp/g1;->a()Z

    .line 1556
    .line 1557
    .line 1558
    move-result v0

    .line 1559
    if-eqz v0, :cond_35

    .line 1560
    .line 1561
    const-string v0, "android.permission.INTERNET"

    .line 1562
    .line 1563
    move-object/from16 v3, v28

    .line 1564
    .line 1565
    invoke-virtual {v3, v0}, Lvp/d4;->x0(Ljava/lang/String;)Z

    .line 1566
    .line 1567
    .line 1568
    move-result v0

    .line 1569
    if-nez v0, :cond_31

    .line 1570
    .line 1571
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1572
    .line 1573
    .line 1574
    const-string v0, "App is missing INTERNET permission"

    .line 1575
    .line 1576
    move-object/from16 v2, v27

    .line 1577
    .line 1578
    invoke-virtual {v2, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1579
    .line 1580
    .line 1581
    goto :goto_1d

    .line 1582
    :cond_31
    move-object/from16 v2, v27

    .line 1583
    .line 1584
    :goto_1d
    const-string v0, "android.permission.ACCESS_NETWORK_STATE"

    .line 1585
    .line 1586
    invoke-virtual {v3, v0}, Lvp/d4;->x0(Ljava/lang/String;)Z

    .line 1587
    .line 1588
    .line 1589
    move-result v0

    .line 1590
    if-nez v0, :cond_32

    .line 1591
    .line 1592
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1593
    .line 1594
    .line 1595
    const-string v0, "App is missing ACCESS_NETWORK_STATE permission"

    .line 1596
    .line 1597
    invoke-virtual {v2, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1598
    .line 1599
    .line 1600
    :cond_32
    move-object/from16 v10, v26

    .line 1601
    .line 1602
    iget-object v0, v10, Lvp/g1;->d:Landroid/content/Context;

    .line 1603
    .line 1604
    invoke-static {v0}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 1605
    .line 1606
    .line 1607
    move-result-object v7

    .line 1608
    invoke-virtual {v7}, Lcq/r1;->d()Z

    .line 1609
    .line 1610
    .line 1611
    move-result v7

    .line 1612
    if-nez v7, :cond_34

    .line 1613
    .line 1614
    invoke-virtual {v1}, Lvp/h;->d0()Z

    .line 1615
    .line 1616
    .line 1617
    move-result v7

    .line 1618
    if-nez v7, :cond_34

    .line 1619
    .line 1620
    invoke-static {v0}, Lvp/d4;->Q0(Landroid/content/Context;)Z

    .line 1621
    .line 1622
    .line 1623
    move-result v7

    .line 1624
    if-nez v7, :cond_33

    .line 1625
    .line 1626
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1627
    .line 1628
    .line 1629
    const-string v7, "AppMeasurementReceiver not registered/enabled"

    .line 1630
    .line 1631
    invoke-virtual {v2, v7}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1632
    .line 1633
    .line 1634
    :cond_33
    invoke-static {v0}, Lvp/d4;->t0(Landroid/content/Context;)Z

    .line 1635
    .line 1636
    .line 1637
    move-result v0

    .line 1638
    if-nez v0, :cond_34

    .line 1639
    .line 1640
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1641
    .line 1642
    .line 1643
    const-string v0, "AppMeasurementService not registered/enabled"

    .line 1644
    .line 1645
    invoke-virtual {v2, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1646
    .line 1647
    .line 1648
    :cond_34
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1649
    .line 1650
    .line 1651
    const-string v0, "Uploading is not possible. App measurement disabled"

    .line 1652
    .line 1653
    invoke-virtual {v2, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1654
    .line 1655
    .line 1656
    :goto_1e
    move-object/from16 v2, v24

    .line 1657
    .line 1658
    goto/16 :goto_24

    .line 1659
    .line 1660
    :cond_35
    move-object/from16 v10, v26

    .line 1661
    .line 1662
    move-object/from16 v3, v28

    .line 1663
    .line 1664
    goto :goto_1e

    .line 1665
    :cond_36
    move-object/from16 v10, v26

    .line 1666
    .line 1667
    move-object/from16 v3, v28

    .line 1668
    .line 1669
    invoke-virtual {v10}, Lvp/g1;->q()Lvp/h0;

    .line 1670
    .line 1671
    .line 1672
    move-result-object v11

    .line 1673
    invoke-virtual {v11}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1674
    .line 1675
    .line 1676
    move-result-object v11

    .line 1677
    invoke-static {v11}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1678
    .line 1679
    .line 1680
    move-result v11

    .line 1681
    if-nez v11, :cond_3a

    .line 1682
    .line 1683
    invoke-virtual {v10}, Lvp/g1;->q()Lvp/h0;

    .line 1684
    .line 1685
    .line 1686
    move-result-object v11

    .line 1687
    invoke-virtual {v11}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1688
    .line 1689
    .line 1690
    move-result-object v11

    .line 1691
    invoke-virtual {v9}, Lap0/o;->a0()V

    .line 1692
    .line 1693
    .line 1694
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1695
    .line 1696
    .line 1697
    move-result-object v13

    .line 1698
    const-string v14, "gmp_app_id"

    .line 1699
    .line 1700
    const/4 v15, 0x0

    .line 1701
    invoke-interface {v13, v14, v15}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1702
    .line 1703
    .line 1704
    move-result-object v13

    .line 1705
    invoke-static {v11}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1706
    .line 1707
    .line 1708
    move-result v15

    .line 1709
    invoke-static {v13}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1710
    .line 1711
    .line 1712
    move-result v16

    .line 1713
    if-nez v15, :cond_39

    .line 1714
    .line 1715
    if-nez v16, :cond_39

    .line 1716
    .line 1717
    invoke-static {v11}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 1718
    .line 1719
    .line 1720
    invoke-virtual {v11, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1721
    .line 1722
    .line 1723
    move-result v11

    .line 1724
    if-nez v11, :cond_39

    .line 1725
    .line 1726
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1727
    .line 1728
    .line 1729
    const-string v11, "Rechecking which service to use due to a GMP App Id change"

    .line 1730
    .line 1731
    move-object/from16 v13, p0

    .line 1732
    .line 1733
    invoke-virtual {v13, v11}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1734
    .line 1735
    .line 1736
    invoke-virtual {v9}, Lap0/o;->a0()V

    .line 1737
    .line 1738
    .line 1739
    invoke-virtual {v9}, Lap0/o;->a0()V

    .line 1740
    .line 1741
    .line 1742
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1743
    .line 1744
    .line 1745
    move-result-object v11

    .line 1746
    const-string v13, "measurement_enabled"

    .line 1747
    .line 1748
    invoke-interface {v11, v13}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 1749
    .line 1750
    .line 1751
    move-result v11

    .line 1752
    if-eqz v11, :cond_37

    .line 1753
    .line 1754
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1755
    .line 1756
    .line 1757
    move-result-object v11

    .line 1758
    const/4 v15, 0x1

    .line 1759
    invoke-interface {v11, v13, v15}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 1760
    .line 1761
    .line 1762
    move-result v11

    .line 1763
    invoke-static {v11}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1764
    .line 1765
    .line 1766
    move-result-object v11

    .line 1767
    goto :goto_1f

    .line 1768
    :cond_37
    const/4 v11, 0x0

    .line 1769
    :goto_1f
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1770
    .line 1771
    .line 1772
    move-result-object v15

    .line 1773
    invoke-interface {v15}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 1774
    .line 1775
    .line 1776
    move-result-object v15

    .line 1777
    invoke-interface {v15}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;

    .line 1778
    .line 1779
    .line 1780
    invoke-interface {v15}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 1781
    .line 1782
    .line 1783
    if-eqz v11, :cond_38

    .line 1784
    .line 1785
    invoke-virtual {v9}, Lap0/o;->a0()V

    .line 1786
    .line 1787
    .line 1788
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1789
    .line 1790
    .line 1791
    move-result-object v15

    .line 1792
    invoke-interface {v15}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 1793
    .line 1794
    .line 1795
    move-result-object v15

    .line 1796
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1797
    .line 1798
    .line 1799
    move-result v11

    .line 1800
    invoke-interface {v15, v13, v11}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 1801
    .line 1802
    .line 1803
    invoke-interface {v15}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 1804
    .line 1805
    .line 1806
    :cond_38
    invoke-virtual {v10}, Lvp/g1;->n()Lvp/j0;

    .line 1807
    .line 1808
    .line 1809
    move-result-object v11

    .line 1810
    invoke-virtual {v11}, Lvp/j0;->e0()V

    .line 1811
    .line 1812
    .line 1813
    iget-object v11, v10, Lvp/g1;->u:Lvp/d3;

    .line 1814
    .line 1815
    invoke-virtual {v11}, Lvp/d3;->i0()V

    .line 1816
    .line 1817
    .line 1818
    iget-object v11, v10, Lvp/g1;->u:Lvp/d3;

    .line 1819
    .line 1820
    invoke-virtual {v11}, Lvp/d3;->g0()V

    .line 1821
    .line 1822
    .line 1823
    invoke-virtual {v0, v7, v8}, La8/s1;->h(J)V

    .line 1824
    .line 1825
    .line 1826
    move-object/from16 v0, v25

    .line 1827
    .line 1828
    const/4 v15, 0x0

    .line 1829
    invoke-virtual {v0, v15}, La8/b;->u(Ljava/lang/String;)V

    .line 1830
    .line 1831
    .line 1832
    goto :goto_20

    .line 1833
    :cond_39
    move-object/from16 v0, v25

    .line 1834
    .line 1835
    :goto_20
    invoke-virtual {v10}, Lvp/g1;->q()Lvp/h0;

    .line 1836
    .line 1837
    .line 1838
    move-result-object v7

    .line 1839
    invoke-virtual {v7}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1840
    .line 1841
    .line 1842
    move-result-object v7

    .line 1843
    invoke-virtual {v9}, Lap0/o;->a0()V

    .line 1844
    .line 1845
    .line 1846
    invoke-virtual {v9}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1847
    .line 1848
    .line 1849
    move-result-object v8

    .line 1850
    invoke-interface {v8}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 1851
    .line 1852
    .line 1853
    move-result-object v8

    .line 1854
    invoke-interface {v8, v14, v7}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 1855
    .line 1856
    .line 1857
    invoke-interface {v8}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 1858
    .line 1859
    .line 1860
    goto :goto_21

    .line 1861
    :cond_3a
    move-object/from16 v0, v25

    .line 1862
    .line 1863
    :goto_21
    invoke-virtual {v9}, Lvp/w0;->h0()Lvp/s1;

    .line 1864
    .line 1865
    .line 1866
    move-result-object v7

    .line 1867
    invoke-virtual {v7, v2}, Lvp/s1;->i(Lvp/r1;)Z

    .line 1868
    .line 1869
    .line 1870
    move-result v2

    .line 1871
    if-nez v2, :cond_3b

    .line 1872
    .line 1873
    const/4 v14, 0x0

    .line 1874
    invoke-virtual {v0, v14}, La8/b;->u(Ljava/lang/String;)V

    .line 1875
    .line 1876
    .line 1877
    :cond_3b
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1878
    .line 1879
    .line 1880
    invoke-virtual {v0}, La8/b;->t()Ljava/lang/String;

    .line 1881
    .line 1882
    .line 1883
    move-result-object v0

    .line 1884
    iget-object v2, v12, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 1885
    .line 1886
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 1887
    .line 1888
    .line 1889
    move-object/from16 v13, v23

    .line 1890
    .line 1891
    :try_start_6
    iget-object v0, v13, Lvp/g1;->d:Landroid/content/Context;

    .line 1892
    .line 1893
    invoke-virtual {v0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 1894
    .line 1895
    .line 1896
    move-result-object v0

    .line 1897
    const-string v2, "com.google.firebase.remoteconfig.FirebaseRemoteConfig"

    .line 1898
    .line 1899
    invoke-virtual {v0, v2}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_6
    .catch Ljava/lang/ClassNotFoundException; {:try_start_6 .. :try_end_6} :catch_6

    .line 1900
    .line 1901
    .line 1902
    :cond_3c
    move-object/from16 v2, v24

    .line 1903
    .line 1904
    goto :goto_22

    .line 1905
    :catch_6
    iget-object v0, v9, Lvp/w0;->z:La8/b;

    .line 1906
    .line 1907
    invoke-virtual {v0}, La8/b;->t()Ljava/lang/String;

    .line 1908
    .line 1909
    .line 1910
    move-result-object v2

    .line 1911
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1912
    .line 1913
    .line 1914
    move-result v2

    .line 1915
    if-nez v2, :cond_3c

    .line 1916
    .line 1917
    invoke-static/range {v24 .. v24}, Lvp/g1;->k(Lvp/n1;)V

    .line 1918
    .line 1919
    .line 1920
    move-object/from16 v2, v24

    .line 1921
    .line 1922
    iget-object v7, v2, Lvp/p0;->m:Lvp/n0;

    .line 1923
    .line 1924
    const-string v8, "Remote config removed with active feature rollouts"

    .line 1925
    .line 1926
    invoke-virtual {v7, v8}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1927
    .line 1928
    .line 1929
    const/4 v14, 0x0

    .line 1930
    invoke-virtual {v0, v14}, La8/b;->u(Ljava/lang/String;)V

    .line 1931
    .line 1932
    .line 1933
    :goto_22
    invoke-virtual {v10}, Lvp/g1;->q()Lvp/h0;

    .line 1934
    .line 1935
    .line 1936
    move-result-object v0

    .line 1937
    invoke-virtual {v0}, Lvp/h0;->h0()Ljava/lang/String;

    .line 1938
    .line 1939
    .line 1940
    move-result-object v0

    .line 1941
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1942
    .line 1943
    .line 1944
    move-result v0

    .line 1945
    if-nez v0, :cond_40

    .line 1946
    .line 1947
    invoke-virtual {v10}, Lvp/g1;->a()Z

    .line 1948
    .line 1949
    .line 1950
    move-result v0

    .line 1951
    iget-object v7, v9, Lvp/w0;->g:Landroid/content/SharedPreferences;

    .line 1952
    .line 1953
    if-nez v7, :cond_3d

    .line 1954
    .line 1955
    move v8, v6

    .line 1956
    goto :goto_23

    .line 1957
    :cond_3d
    const-string v8, "deferred_analytics_collection"

    .line 1958
    .line 1959
    invoke-interface {v7, v8}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 1960
    .line 1961
    .line 1962
    move-result v8

    .line 1963
    :goto_23
    if-nez v8, :cond_3e

    .line 1964
    .line 1965
    invoke-virtual {v1}, Lvp/h;->n0()Z

    .line 1966
    .line 1967
    .line 1968
    move-result v7

    .line 1969
    if-nez v7, :cond_3e

    .line 1970
    .line 1971
    xor-int/lit8 v7, v0, 0x1

    .line 1972
    .line 1973
    invoke-virtual {v9, v7}, Lvp/w0;->j0(Z)V

    .line 1974
    .line 1975
    .line 1976
    :cond_3e
    if-eqz v0, :cond_3f

    .line 1977
    .line 1978
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1979
    .line 1980
    .line 1981
    invoke-virtual {v12}, Lvp/j2;->m0()V

    .line 1982
    .line 1983
    .line 1984
    :cond_3f
    iget-object v0, v10, Lvp/g1;->k:Lvp/k3;

    .line 1985
    .line 1986
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 1987
    .line 1988
    .line 1989
    iget-object v0, v0, Lvp/k3;->i:Lt1/j0;

    .line 1990
    .line 1991
    invoke-virtual {v0}, Lt1/j0;->o()V

    .line 1992
    .line 1993
    .line 1994
    invoke-virtual {v10}, Lvp/g1;->o()Lvp/d3;

    .line 1995
    .line 1996
    .line 1997
    move-result-object v0

    .line 1998
    new-instance v7, Ljava/util/concurrent/atomic/AtomicReference;

    .line 1999
    .line 2000
    invoke-direct {v7}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 2001
    .line 2002
    .line 2003
    invoke-virtual {v0, v7}, Lvp/d3;->e0(Ljava/util/concurrent/atomic/AtomicReference;)V

    .line 2004
    .line 2005
    .line 2006
    invoke-virtual {v10}, Lvp/g1;->o()Lvp/d3;

    .line 2007
    .line 2008
    .line 2009
    move-result-object v0

    .line 2010
    iget-object v7, v9, Lvp/w0;->C:Lun/a;

    .line 2011
    .line 2012
    invoke-virtual {v7}, Lun/a;->b()Landroid/os/Bundle;

    .line 2013
    .line 2014
    .line 2015
    move-result-object v7

    .line 2016
    invoke-virtual {v0, v7}, Lvp/d3;->f0(Landroid/os/Bundle;)V

    .line 2017
    .line 2018
    .line 2019
    :cond_40
    :goto_24
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 2020
    .line 2021
    .line 2022
    sget-object v0, Lvp/z;->Q0:Lvp/y;

    .line 2023
    .line 2024
    const/4 v14, 0x0

    .line 2025
    invoke-virtual {v1, v14, v0}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 2026
    .line 2027
    .line 2028
    move-result v0

    .line 2029
    if-eqz v0, :cond_44

    .line 2030
    .line 2031
    invoke-virtual {v3}, Lap0/o;->a0()V

    .line 2032
    .line 2033
    .line 2034
    invoke-virtual {v3}, Lvp/d4;->v0()J

    .line 2035
    .line 2036
    .line 2037
    move-result-wide v0

    .line 2038
    cmp-long v0, v0, v20

    .line 2039
    .line 2040
    if-nez v0, :cond_41

    .line 2041
    .line 2042
    const/4 v6, 0x1

    .line 2043
    :cond_41
    if-eqz v6, :cond_44

    .line 2044
    .line 2045
    sget-object v0, Lvp/z;->x0:Lvp/y;

    .line 2046
    .line 2047
    invoke-virtual {v0, v14}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2048
    .line 2049
    .line 2050
    move-result-object v0

    .line 2051
    check-cast v0, Ljava/lang/Integer;

    .line 2052
    .line 2053
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 2054
    .line 2055
    .line 2056
    move-result v0

    .line 2057
    int-to-long v0, v0

    .line 2058
    new-instance v3, Ljava/util/Random;

    .line 2059
    .line 2060
    invoke-direct {v3}, Ljava/util/Random;-><init>()V

    .line 2061
    .line 2062
    .line 2063
    const/16 v6, 0x1388

    .line 2064
    .line 2065
    invoke-virtual {v3, v6}, Ljava/util/Random;->nextInt(I)I

    .line 2066
    .line 2067
    .line 2068
    move-result v3

    .line 2069
    const-wide/16 v6, 0x3e8

    .line 2070
    .line 2071
    mul-long/2addr v0, v6

    .line 2072
    int-to-long v6, v3

    .line 2073
    iget-object v3, v10, Lvp/g1;->n:Lto/a;

    .line 2074
    .line 2075
    add-long/2addr v0, v6

    .line 2076
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2077
    .line 2078
    .line 2079
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2080
    .line 2081
    .line 2082
    move-result-wide v6

    .line 2083
    sub-long/2addr v0, v6

    .line 2084
    const-wide/16 v6, 0x1f4

    .line 2085
    .line 2086
    invoke-static {v6, v7, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 2087
    .line 2088
    .line 2089
    move-result-wide v0

    .line 2090
    cmp-long v3, v0, v6

    .line 2091
    .line 2092
    if-lez v3, :cond_42

    .line 2093
    .line 2094
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 2095
    .line 2096
    .line 2097
    const-string v2, "Waiting to fetch trigger URIs until some time after boot. Delay in millis"

    .line 2098
    .line 2099
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2100
    .line 2101
    .line 2102
    move-result-object v3

    .line 2103
    invoke-virtual {v4, v3, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2104
    .line 2105
    .line 2106
    :cond_42
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 2107
    .line 2108
    .line 2109
    invoke-virtual {v12}, Lvp/x;->a0()V

    .line 2110
    .line 2111
    .line 2112
    iget-object v2, v12, Lvp/j2;->p:Lvp/x1;

    .line 2113
    .line 2114
    if-nez v2, :cond_43

    .line 2115
    .line 2116
    new-instance v2, Lvp/x1;

    .line 2117
    .line 2118
    const/4 v3, 0x0

    .line 2119
    invoke-direct {v2, v12, v5, v3}, Lvp/x1;-><init>(Lvp/j2;Lvp/o1;I)V

    .line 2120
    .line 2121
    .line 2122
    iput-object v2, v12, Lvp/j2;->p:Lvp/x1;

    .line 2123
    .line 2124
    :cond_43
    iget-object v2, v12, Lvp/j2;->p:Lvp/x1;

    .line 2125
    .line 2126
    invoke-virtual {v2, v0, v1}, Lvp/o;->b(J)V

    .line 2127
    .line 2128
    .line 2129
    :cond_44
    iget-object v0, v9, Lvp/w0;->s:Lvp/v0;

    .line 2130
    .line 2131
    const/4 v13, 0x1

    .line 2132
    invoke-virtual {v0, v13}, Lvp/v0;->b(Z)V

    .line 2133
    .line 2134
    .line 2135
    return-void

    .line 2136
    :cond_45
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2137
    .line 2138
    move-object/from16 v15, v23

    .line 2139
    .line 2140
    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2141
    .line 2142
    .line 2143
    throw v0

    .line 2144
    :cond_46
    move-object v15, v5

    .line 2145
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2146
    .line 2147
    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2148
    .line 2149
    .line 2150
    throw v0

    .line 2151
    :cond_47
    move-object v15, v5

    .line 2152
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2153
    .line 2154
    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2155
    .line 2156
    .line 2157
    throw v0

    .line 2158
    :cond_48
    move-object v15, v5

    .line 2159
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2160
    .line 2161
    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2162
    .line 2163
    .line 2164
    throw v0
.end method

.method private final d()V
    .locals 4

    .line 1
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/c3;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    const/4 v1, 0x0

    .line 7
    :try_start_0
    iput-boolean v1, v0, Lvp/c3;->a:Z

    .line 8
    .line 9
    iget-object v1, v0, Lvp/c3;->c:Lvp/d3;

    .line 10
    .line 11
    invoke-virtual {v1}, Lvp/d3;->r0()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Lvp/g1;

    .line 20
    .line 21
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 22
    .line 23
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    iget-object v2, v2, Lvp/p0;->q:Lvp/n0;

    .line 27
    .line 28
    const-string v3, "Connected to remote service"

    .line 29
    .line 30
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-object v2, p0, Llr/b;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v2, Lvp/c0;

    .line 36
    .line 37
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 38
    .line 39
    .line 40
    iput-object v2, v1, Lvp/d3;->h:Lvp/c0;

    .line 41
    .line 42
    invoke-virtual {v1}, Lvp/d3;->n0()V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Lvp/d3;->p0()V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    goto :goto_1

    .line 51
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p0, Lvp/c3;

    .line 55
    .line 56
    iget-object p0, p0, Lvp/c3;->c:Lvp/d3;

    .line 57
    .line 58
    iget-object v0, p0, Lvp/d3;->k:Ljava/util/concurrent/ScheduledExecutorService;

    .line 59
    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    .line 63
    .line 64
    .line 65
    const/4 v0, 0x0

    .line 66
    iput-object v0, p0, Lvp/d3;->k:Ljava/util/concurrent/ScheduledExecutorService;

    .line 67
    .line 68
    :cond_1
    return-void

    .line 69
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 70
    throw p0
.end method


# virtual methods
.method public e()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    :try_start_0
    iget-object v2, p0, Llr/b;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v2, Lhs/k;

    .line 6
    .line 7
    iget-object v2, v2, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 8
    .line 9
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 10
    const/4 v3, 0x1

    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    :try_start_1
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lhs/k;

    .line 16
    .line 17
    iget v4, v0, Lhs/k;->f:I

    .line 18
    .line 19
    const/4 v5, 0x4

    .line 20
    if-ne v4, v5, :cond_0

    .line 21
    .line 22
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    :goto_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 30
    .line 31
    .line 32
    goto :goto_2

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_5

    .line 35
    :cond_0
    :try_start_2
    iget-wide v6, v0, Lhs/k;->g:J

    .line 36
    .line 37
    const-wide/16 v8, 0x1

    .line 38
    .line 39
    add-long/2addr v6, v8

    .line 40
    iput-wide v6, v0, Lhs/k;->g:J

    .line 41
    .line 42
    iput v5, v0, Lhs/k;->f:I

    .line 43
    .line 44
    move v0, v3

    .line 45
    :cond_1
    iget-object v4, p0, Llr/b;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v4, Lhs/k;

    .line 48
    .line 49
    iget-object v4, v4, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    check-cast v4, Ljava/lang/Runnable;

    .line 56
    .line 57
    iput-object v4, p0, Llr/b;->e:Ljava/lang/Object;

    .line 58
    .line 59
    if-nez v4, :cond_3

    .line 60
    .line 61
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Lhs/k;

    .line 64
    .line 65
    iput v3, p0, Lhs/k;->f:I

    .line 66
    .line 67
    monitor-exit v2

    .line 68
    if-eqz v1, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    :goto_2
    return-void

    .line 72
    :cond_3
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 73
    :try_start_3
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 74
    .line 75
    .line 76
    move-result v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 77
    or-int/2addr v1, v2

    .line 78
    const/4 v2, 0x0

    .line 79
    :try_start_4
    iget-object v3, p0, Llr/b;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v3, Ljava/lang/Runnable;

    .line 82
    .line 83
    invoke-interface {v3}, Ljava/lang/Runnable;->run()V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 84
    .line 85
    .line 86
    :goto_3
    :try_start_5
    iput-object v2, p0, Llr/b;->e:Ljava/lang/Object;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :catchall_1
    move-exception p0

    .line 90
    goto :goto_6

    .line 91
    :catchall_2
    move-exception v0

    .line 92
    goto :goto_4

    .line 93
    :catch_0
    move-exception v3

    .line 94
    :try_start_6
    sget-object v4, Lhs/k;->i:Ljava/util/logging/Logger;

    .line 95
    .line 96
    sget-object v5, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 97
    .line 98
    new-instance v6, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 101
    .line 102
    .line 103
    const-string v7, "Exception while executing runnable "

    .line 104
    .line 105
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v7, p0, Llr/b;->e:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v7, Ljava/lang/Runnable;

    .line 111
    .line 112
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    invoke-virtual {v4, v5, v6, v3}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :goto_4
    :try_start_7
    iput-object v2, p0, Llr/b;->e:Ljava/lang/Object;

    .line 124
    .line 125
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 126
    :goto_5
    :try_start_8
    monitor-exit v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 127
    :try_start_9
    throw p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 128
    :goto_6
    if-eqz v1, :cond_4

    .line 129
    .line 130
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V

    .line 135
    .line 136
    .line 137
    :cond_4
    throw p0
.end method

.method public final run()V
    .locals 14

    .line 1
    iget v0, p0, Llr/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lj1/a;

    .line 9
    .line 10
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/graphics/Typeface;

    .line 13
    .line 14
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lp5/b;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Lp5/b;->i(Landroid/graphics/Typeface;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void

    .line 24
    :pswitch_0
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Lvy0/l;

    .line 27
    .line 28
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lvy0/b1;

    .line 31
    .line 32
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {v0, p0, v1}, Lvy0/l;->D(Lvy0/x;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :pswitch_1
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Lvp/z3;

    .line 41
    .line 42
    invoke-virtual {v0}, Lvp/z3;->B()V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Ljava/lang/Runnable;

    .line 48
    .line 49
    invoke-virtual {v0}, Lvp/z3;->f()Lvp/e1;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {v1}, Lvp/e1;->a0()V

    .line 54
    .line 55
    .line 56
    iget-object v1, v0, Lvp/z3;->s:Ljava/util/ArrayList;

    .line 57
    .line 58
    if-nez v1, :cond_1

    .line 59
    .line 60
    new-instance v1, Ljava/util/ArrayList;

    .line 61
    .line 62
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 63
    .line 64
    .line 65
    iput-object v1, v0, Lvp/z3;->s:Ljava/util/ArrayList;

    .line 66
    .line 67
    :cond_1
    iget-object v1, v0, Lvp/z3;->s:Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Lvp/z3;->q()V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :pswitch_2
    invoke-direct {p0}, Llr/b;->d()V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :pswitch_3
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Lvp/c3;

    .line 83
    .line 84
    iget-object v0, v0, Lvp/c3;->c:Lvp/d3;

    .line 85
    .line 86
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast p0, Landroid/content/ComponentName;

    .line 89
    .line 90
    invoke-virtual {v0, p0}, Lvp/d3;->l0(Landroid/content/ComponentName;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :pswitch_4
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v0, Lvp/d3;

    .line 97
    .line 98
    iget-object v1, v0, Lvp/d3;->h:Lvp/c0;

    .line 99
    .line 100
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 101
    .line 102
    move-object v7, v2

    .line 103
    check-cast v7, Lvp/g1;

    .line 104
    .line 105
    if-nez v1, :cond_2

    .line 106
    .line 107
    iget-object p0, v7, Lvp/g1;->i:Lvp/p0;

    .line 108
    .line 109
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 110
    .line 111
    .line 112
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 113
    .line 114
    const-string v0, "Failed to send current screen to service"

    .line 115
    .line 116
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_2
    :try_start_0
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast p0, Lvp/r2;

    .line 123
    .line 124
    if-nez p0, :cond_3

    .line 125
    .line 126
    iget-object p0, v7, Lvp/g1;->d:Landroid/content/Context;

    .line 127
    .line 128
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v6

    .line 132
    const-wide/16 v2, 0x0

    .line 133
    .line 134
    const/4 v4, 0x0

    .line 135
    const/4 v5, 0x0

    .line 136
    invoke-interface/range {v1 .. v6}, Lvp/c0;->w(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    goto :goto_0

    .line 140
    :catch_0
    move-exception v0

    .line 141
    move-object p0, v0

    .line 142
    goto :goto_1

    .line 143
    :cond_3
    iget-wide v2, p0, Lvp/r2;->c:J

    .line 144
    .line 145
    iget-object v4, p0, Lvp/r2;->a:Ljava/lang/String;

    .line 146
    .line 147
    iget-object v5, p0, Lvp/r2;->b:Ljava/lang/String;

    .line 148
    .line 149
    iget-object p0, v7, Lvp/g1;->d:Landroid/content/Context;

    .line 150
    .line 151
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    invoke-interface/range {v1 .. v6}, Lvp/c0;->w(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :goto_0
    invoke-virtual {v0}, Lvp/d3;->n0()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 159
    .line 160
    .line 161
    goto :goto_2

    .line 162
    :goto_1
    iget-object v0, v7, Lvp/g1;->i:Lvp/p0;

    .line 163
    .line 164
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 165
    .line 166
    .line 167
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 168
    .line 169
    const-string v1, "Failed to send current screen to the service"

    .line 170
    .line 171
    invoke-virtual {v0, p0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    :goto_2
    return-void

    .line 175
    :pswitch_5
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Lvp/j2;

    .line 178
    .line 179
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v1, Lvp/g1;

    .line 182
    .line 183
    iget-object v2, v1, Lvp/g1;->h:Lvp/w0;

    .line 184
    .line 185
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 186
    .line 187
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v2}, Lap0/o;->a0()V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v2}, Lap0/o;->a0()V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 197
    .line 198
    .line 199
    move-result-object v3

    .line 200
    const-string v4, "dma_consent_settings"

    .line 201
    .line 202
    const/4 v5, 0x0

    .line 203
    invoke-interface {v3, v4, v5}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v3

    .line 207
    invoke-static {v3}, Lvp/p;->b(Ljava/lang/String;)Lvp/p;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast p0, Lvp/p;

    .line 214
    .line 215
    iget v5, p0, Lvp/p;->a:I

    .line 216
    .line 217
    iget v3, v3, Lvp/p;->a:I

    .line 218
    .line 219
    invoke-static {v5, v3}, Lvp/s1;->l(II)Z

    .line 220
    .line 221
    .line 222
    move-result v3

    .line 223
    if-eqz v3, :cond_5

    .line 224
    .line 225
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 230
    .line 231
    .line 232
    move-result-object v2

    .line 233
    iget-object v3, p0, Lvp/p;->b:Ljava/lang/String;

    .line 234
    .line 235
    invoke-interface {v2, v4, v3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 236
    .line 237
    .line 238
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 239
    .line 240
    .line 241
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 242
    .line 243
    .line 244
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 245
    .line 246
    const-string v2, "Setting DMA consent(FE)"

    .line 247
    .line 248
    invoke-virtual {v1, p0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p0, Lvp/g1;

    .line 254
    .line 255
    invoke-virtual {p0}, Lvp/g1;->o()Lvp/d3;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    invoke-virtual {v0}, Lvp/d3;->k0()Z

    .line 260
    .line 261
    .line 262
    move-result v0

    .line 263
    if-eqz v0, :cond_4

    .line 264
    .line 265
    invoke-virtual {p0}, Lvp/g1;->o()Lvp/d3;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 270
    .line 271
    .line 272
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 273
    .line 274
    .line 275
    new-instance v0, Lvp/b3;

    .line 276
    .line 277
    const/4 v1, 0x1

    .line 278
    invoke-direct {v0, p0, v1}, Lvp/b3;-><init>(Lvp/d3;I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {p0, v0}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 282
    .line 283
    .line 284
    goto :goto_3

    .line 285
    :cond_4
    invoke-virtual {p0}, Lvp/g1;->o()Lvp/d3;

    .line 286
    .line 287
    .line 288
    move-result-object p0

    .line 289
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 290
    .line 291
    .line 292
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 293
    .line 294
    .line 295
    invoke-virtual {p0}, Lvp/d3;->j0()Z

    .line 296
    .line 297
    .line 298
    move-result v0

    .line 299
    if-eqz v0, :cond_6

    .line 300
    .line 301
    const/4 v0, 0x0

    .line 302
    invoke-virtual {p0, v0}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    new-instance v1, Lvp/z2;

    .line 307
    .line 308
    const/4 v2, 0x1

    .line 309
    invoke-direct {v1, p0, v0, v2}, Lvp/z2;-><init>(Lvp/d3;Lvp/f4;I)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {p0, v1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 313
    .line 314
    .line 315
    goto :goto_3

    .line 316
    :cond_5
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 317
    .line 318
    .line 319
    iget-object p0, v1, Lvp/p0;->p:Lvp/n0;

    .line 320
    .line 321
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    const-string v1, "Lower precedence consent source ignored, proposed source"

    .line 326
    .line 327
    invoke-virtual {p0, v0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    :cond_6
    :goto_3
    return-void

    .line 331
    :pswitch_6
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 332
    .line 333
    check-cast v0, Lcom/google/android/gms/internal/measurement/m0;

    .line 334
    .line 335
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 336
    .line 337
    check-cast p0, Lvp/j2;

    .line 338
    .line 339
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 340
    .line 341
    check-cast v1, Lvp/g1;

    .line 342
    .line 343
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 344
    .line 345
    check-cast p0, Lvp/g1;

    .line 346
    .line 347
    iget-object v1, v1, Lvp/g1;->k:Lvp/k3;

    .line 348
    .line 349
    invoke-static {v1}, Lvp/g1;->i(Lvp/b0;)V

    .line 350
    .line 351
    .line 352
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v1, Lvp/g1;

    .line 355
    .line 356
    iget-object v2, v1, Lvp/g1;->h:Lvp/w0;

    .line 357
    .line 358
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 359
    .line 360
    .line 361
    invoke-virtual {v2}, Lvp/w0;->h0()Lvp/s1;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    sget-object v4, Lvp/r1;->f:Lvp/r1;

    .line 366
    .line 367
    invoke-virtual {v3, v4}, Lvp/s1;->i(Lvp/r1;)Z

    .line 368
    .line 369
    .line 370
    move-result v3

    .line 371
    const/4 v4, 0x0

    .line 372
    if-nez v3, :cond_8

    .line 373
    .line 374
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 375
    .line 376
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 377
    .line 378
    .line 379
    iget-object v1, v1, Lvp/p0;->o:Lvp/n0;

    .line 380
    .line 381
    const-string v2, "Analytics storage consent denied; will not get session id"

    .line 382
    .line 383
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    :cond_7
    :goto_4
    move-object v1, v4

    .line 387
    goto :goto_5

    .line 388
    :cond_8
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 389
    .line 390
    .line 391
    iget-object v3, v2, Lvp/w0;->u:La8/s1;

    .line 392
    .line 393
    iget-object v1, v1, Lvp/g1;->n:Lto/a;

    .line 394
    .line 395
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 396
    .line 397
    .line 398
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 399
    .line 400
    .line 401
    move-result-wide v5

    .line 402
    invoke-virtual {v2, v5, v6}, Lvp/w0;->k0(J)Z

    .line 403
    .line 404
    .line 405
    move-result v1

    .line 406
    if-nez v1, :cond_7

    .line 407
    .line 408
    invoke-virtual {v3}, La8/s1;->g()J

    .line 409
    .line 410
    .line 411
    move-result-wide v1

    .line 412
    const-wide/16 v5, 0x0

    .line 413
    .line 414
    cmp-long v1, v1, v5

    .line 415
    .line 416
    if-nez v1, :cond_9

    .line 417
    .line 418
    goto :goto_4

    .line 419
    :cond_9
    invoke-virtual {v3}, La8/s1;->g()J

    .line 420
    .line 421
    .line 422
    move-result-wide v1

    .line 423
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    :goto_5
    if-eqz v1, :cond_a

    .line 428
    .line 429
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 430
    .line 431
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 435
    .line 436
    .line 437
    move-result-wide v1

    .line 438
    invoke-virtual {p0, v0, v1, v2}, Lvp/d4;->J0(Lcom/google/android/gms/internal/measurement/m0;J)V

    .line 439
    .line 440
    .line 441
    goto :goto_6

    .line 442
    :cond_a
    :try_start_1
    invoke-interface {v0, v4}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 443
    .line 444
    .line 445
    goto :goto_6

    .line 446
    :catch_1
    move-exception v0

    .line 447
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 448
    .line 449
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 450
    .line 451
    .line 452
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 453
    .line 454
    const-string v1, "getSessionId failed with exception"

    .line 455
    .line 456
    invoke-virtual {p0, v0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    :goto_6
    return-void

    .line 460
    :pswitch_7
    invoke-direct {p0}, Llr/b;->c()V

    .line 461
    .line 462
    .line 463
    return-void

    .line 464
    :pswitch_8
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 465
    .line 466
    check-cast v0, Lvp/x0;

    .line 467
    .line 468
    iget-object v1, v0, Lvp/x0;->b:Lvp/y0;

    .line 469
    .line 470
    iget-object v1, v1, Lvp/y0;->d:Lvp/g1;

    .line 471
    .line 472
    iget-object v2, v1, Lvp/g1;->j:Lvp/e1;

    .line 473
    .line 474
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 475
    .line 476
    .line 477
    invoke-virtual {v2}, Lvp/e1;->a0()V

    .line 478
    .line 479
    .line 480
    new-instance v2, Landroid/os/Bundle;

    .line 481
    .line 482
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 483
    .line 484
    .line 485
    const-string v3, "package_name"

    .line 486
    .line 487
    iget-object v0, v0, Lvp/x0;->a:Ljava/lang/String;

    .line 488
    .line 489
    invoke-virtual {v2, v3, v0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 490
    .line 491
    .line 492
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 493
    .line 494
    check-cast p0, Lcom/google/android/gms/internal/measurement/c0;

    .line 495
    .line 496
    :try_start_2
    check-cast p0, Lcom/google/android/gms/internal/measurement/a0;

    .line 497
    .line 498
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    invoke-static {v0, v2}, Lcom/google/android/gms/internal/measurement/z;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 503
    .line 504
    .line 505
    const/4 v2, 0x1

    .line 506
    invoke-virtual {p0, v0, v2}, Lbp/a;->Q(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 507
    .line 508
    .line 509
    move-result-object p0

    .line 510
    sget-object v0, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 511
    .line 512
    invoke-static {p0, v0}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 513
    .line 514
    .line 515
    move-result-object v0

    .line 516
    check-cast v0, Landroid/os/Bundle;

    .line 517
    .line 518
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 519
    .line 520
    .line 521
    if-nez v0, :cond_b

    .line 522
    .line 523
    iget-object p0, v1, Lvp/g1;->i:Lvp/p0;

    .line 524
    .line 525
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 526
    .line 527
    .line 528
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 529
    .line 530
    const-string v0, "Install Referrer Service returned a null response"

    .line 531
    .line 532
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 533
    .line 534
    .line 535
    goto :goto_7

    .line 536
    :catch_2
    move-exception v0

    .line 537
    move-object p0, v0

    .line 538
    iget-object v0, v1, Lvp/g1;->i:Lvp/p0;

    .line 539
    .line 540
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 541
    .line 542
    .line 543
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 544
    .line 545
    const-string v2, "Exception occurred while retrieving the Install Referrer"

    .line 546
    .line 547
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 548
    .line 549
    .line 550
    move-result-object p0

    .line 551
    invoke-virtual {v0, p0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    :cond_b
    :goto_7
    iget-object p0, v1, Lvp/g1;->j:Lvp/e1;

    .line 555
    .line 556
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 557
    .line 558
    .line 559
    invoke-virtual {p0}, Lvp/e1;->a0()V

    .line 560
    .line 561
    .line 562
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 563
    .line 564
    const-string v0, "Unexpected call on client side"

    .line 565
    .line 566
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 567
    .line 568
    .line 569
    throw p0

    .line 570
    :pswitch_9
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 571
    .line 572
    check-cast v0, Lq/k;

    .line 573
    .line 574
    iget-object v0, v0, Lq/k;->e:Lq/s;

    .line 575
    .line 576
    iget-object v1, v0, Lq/s;->e:Ljp/he;

    .line 577
    .line 578
    if-nez v1, :cond_c

    .line 579
    .line 580
    new-instance v1, Lq/o;

    .line 581
    .line 582
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 583
    .line 584
    .line 585
    iput-object v1, v0, Lq/s;->e:Ljp/he;

    .line 586
    .line 587
    :cond_c
    iget-object v0, v0, Lq/s;->e:Ljp/he;

    .line 588
    .line 589
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 590
    .line 591
    check-cast p0, Lq/n;

    .line 592
    .line 593
    invoke-virtual {v0, p0}, Ljp/he;->f(Lq/n;)V

    .line 594
    .line 595
    .line 596
    return-void

    .line 597
    :pswitch_a
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 598
    .line 599
    move-object v2, v0

    .line 600
    check-cast v2, Llp/lg;

    .line 601
    .line 602
    sget-object v4, Llp/ub;->v2:Llp/ub;

    .line 603
    .line 604
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 605
    .line 606
    check-cast p0, Lpv/g;

    .line 607
    .line 608
    iget-object v0, v2, Llp/lg;->j:Ljava/util/HashMap;

    .line 609
    .line 610
    invoke-virtual {v0, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 611
    .line 612
    .line 613
    move-result-object v1

    .line 614
    move-object v7, v1

    .line 615
    check-cast v7, Llp/f;

    .line 616
    .line 617
    if-eqz v7, :cond_13

    .line 618
    .line 619
    iget-object v8, v7, Llp/f;->f:Llp/j;

    .line 620
    .line 621
    iget-object v1, v7, Llp/e;->d:Llp/a;

    .line 622
    .line 623
    if-nez v1, :cond_d

    .line 624
    .line 625
    new-instance v1, Llp/a;

    .line 626
    .line 627
    invoke-direct {v1, v7, v8}, Llp/a;-><init>(Llp/f;Ljava/util/Map;)V

    .line 628
    .line 629
    .line 630
    iput-object v1, v7, Llp/e;->d:Llp/a;

    .line 631
    .line 632
    :cond_d
    invoke-virtual {v1}, Llp/a;->iterator()Ljava/util/Iterator;

    .line 633
    .line 634
    .line 635
    move-result-object v9

    .line 636
    :goto_8
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 637
    .line 638
    .line 639
    move-result v1

    .line 640
    if-eqz v1, :cond_12

    .line 641
    .line 642
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 643
    .line 644
    .line 645
    move-result-object v1

    .line 646
    new-instance v3, Ljava/util/ArrayList;

    .line 647
    .line 648
    invoke-virtual {v8, v1}, Llp/j;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 649
    .line 650
    .line 651
    move-result-object v5

    .line 652
    check-cast v5, Ljava/util/Collection;

    .line 653
    .line 654
    if-nez v5, :cond_e

    .line 655
    .line 656
    new-instance v5, Ljava/util/ArrayList;

    .line 657
    .line 658
    const/4 v6, 0x3

    .line 659
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 660
    .line 661
    .line 662
    :cond_e
    check-cast v5, Ljava/util/List;

    .line 663
    .line 664
    instance-of v6, v5, Ljava/util/RandomAccess;

    .line 665
    .line 666
    const/4 v10, 0x0

    .line 667
    if-eqz v6, :cond_f

    .line 668
    .line 669
    new-instance v6, Llp/c;

    .line 670
    .line 671
    invoke-direct {v6, v7, v1, v5, v10}, Lhr/l;-><init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 672
    .line 673
    .line 674
    goto :goto_9

    .line 675
    :cond_f
    new-instance v6, Lhr/l;

    .line 676
    .line 677
    invoke-direct {v6, v7, v1, v5, v10}, Lhr/l;-><init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 678
    .line 679
    .line 680
    :goto_9
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 681
    .line 682
    .line 683
    invoke-static {v3}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 684
    .line 685
    .line 686
    new-instance v5, Ljp/eb;

    .line 687
    .line 688
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 689
    .line 690
    .line 691
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 692
    .line 693
    .line 694
    move-result-object v6

    .line 695
    const-wide/16 v10, 0x0

    .line 696
    .line 697
    :goto_a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 698
    .line 699
    .line 700
    move-result v12

    .line 701
    if-eqz v12, :cond_10

    .line 702
    .line 703
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 704
    .line 705
    .line 706
    move-result-object v12

    .line 707
    check-cast v12, Ljava/lang/Long;

    .line 708
    .line 709
    invoke-virtual {v12}, Ljava/lang/Long;->longValue()J

    .line 710
    .line 711
    .line 712
    move-result-wide v12

    .line 713
    add-long/2addr v10, v12

    .line 714
    goto :goto_a

    .line 715
    :cond_10
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 716
    .line 717
    .line 718
    move-result v6

    .line 719
    int-to-long v12, v6

    .line 720
    div-long/2addr v10, v12

    .line 721
    const-wide v12, 0x7fffffffffffffffL

    .line 722
    .line 723
    .line 724
    .line 725
    .line 726
    and-long/2addr v10, v12

    .line 727
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 728
    .line 729
    .line 730
    move-result-object v6

    .line 731
    iput-object v6, v5, Ljp/eb;->c:Ljava/lang/Long;

    .line 732
    .line 733
    const-wide/high16 v10, 0x4059000000000000L    # 100.0

    .line 734
    .line 735
    invoke-static {v3, v10, v11}, Llp/lg;->a(Ljava/util/ArrayList;D)J

    .line 736
    .line 737
    .line 738
    move-result-wide v10

    .line 739
    and-long/2addr v10, v12

    .line 740
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 741
    .line 742
    .line 743
    move-result-object v6

    .line 744
    iput-object v6, v5, Ljp/eb;->a:Ljava/lang/Long;

    .line 745
    .line 746
    const-wide v10, 0x4052c00000000000L    # 75.0

    .line 747
    .line 748
    .line 749
    .line 750
    .line 751
    invoke-static {v3, v10, v11}, Llp/lg;->a(Ljava/util/ArrayList;D)J

    .line 752
    .line 753
    .line 754
    move-result-wide v10

    .line 755
    and-long/2addr v10, v12

    .line 756
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 757
    .line 758
    .line 759
    move-result-object v6

    .line 760
    iput-object v6, v5, Ljp/eb;->f:Ljava/lang/Long;

    .line 761
    .line 762
    const-wide/high16 v10, 0x4049000000000000L    # 50.0

    .line 763
    .line 764
    invoke-static {v3, v10, v11}, Llp/lg;->a(Ljava/util/ArrayList;D)J

    .line 765
    .line 766
    .line 767
    move-result-wide v10

    .line 768
    and-long/2addr v10, v12

    .line 769
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 770
    .line 771
    .line 772
    move-result-object v6

    .line 773
    iput-object v6, v5, Ljp/eb;->e:Ljava/lang/Long;

    .line 774
    .line 775
    const-wide/high16 v10, 0x4039000000000000L    # 25.0

    .line 776
    .line 777
    invoke-static {v3, v10, v11}, Llp/lg;->a(Ljava/util/ArrayList;D)J

    .line 778
    .line 779
    .line 780
    move-result-wide v10

    .line 781
    and-long/2addr v10, v12

    .line 782
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 783
    .line 784
    .line 785
    move-result-object v6

    .line 786
    iput-object v6, v5, Ljp/eb;->d:Ljava/lang/Long;

    .line 787
    .line 788
    const-wide/16 v10, 0x0

    .line 789
    .line 790
    invoke-static {v3, v10, v11}, Llp/lg;->a(Ljava/util/ArrayList;D)J

    .line 791
    .line 792
    .line 793
    move-result-wide v10

    .line 794
    and-long/2addr v10, v12

    .line 795
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 796
    .line 797
    .line 798
    move-result-object v6

    .line 799
    iput-object v6, v5, Ljp/eb;->b:Ljava/lang/Long;

    .line 800
    .line 801
    new-instance v6, Llp/za;

    .line 802
    .line 803
    invoke-direct {v6, v5}, Llp/za;-><init>(Ljp/eb;)V

    .line 804
    .line 805
    .line 806
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 807
    .line 808
    .line 809
    move-result v3

    .line 810
    iget-object v5, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 811
    .line 812
    check-cast v5, Lpv/a;

    .line 813
    .line 814
    check-cast v1, Llp/r1;

    .line 815
    .line 816
    new-instance v10, Lin/z1;

    .line 817
    .line 818
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 819
    .line 820
    .line 821
    iget-object v5, v5, Lpv/a;->k:Lov/f;

    .line 822
    .line 823
    check-cast v5, Lqv/a;

    .line 824
    .line 825
    invoke-virtual {v5}, Lqv/a;->a()Z

    .line 826
    .line 827
    .line 828
    move-result v5

    .line 829
    if-eqz v5, :cond_11

    .line 830
    .line 831
    sget-object v5, Llp/sb;->f:Llp/sb;

    .line 832
    .line 833
    goto :goto_b

    .line 834
    :cond_11
    sget-object v5, Llp/sb;->e:Llp/sb;

    .line 835
    .line 836
    :goto_b
    iput-object v5, v10, Lin/z1;->c:Ljava/lang/Object;

    .line 837
    .line 838
    new-instance v5, Llp/f0;

    .line 839
    .line 840
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 841
    .line 842
    .line 843
    const v11, 0x7fffffff

    .line 844
    .line 845
    .line 846
    and-int/2addr v3, v11

    .line 847
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 848
    .line 849
    .line 850
    move-result-object v3

    .line 851
    iput-object v3, v5, Llp/f0;->e:Ljava/lang/Object;

    .line 852
    .line 853
    iput-object v1, v5, Llp/f0;->d:Ljava/lang/Object;

    .line 854
    .line 855
    iput-object v6, v5, Llp/f0;->f:Ljava/lang/Object;

    .line 856
    .line 857
    new-instance v1, Llp/s1;

    .line 858
    .line 859
    invoke-direct {v1, v5}, Llp/s1;-><init>(Llp/f0;)V

    .line 860
    .line 861
    .line 862
    iput-object v1, v10, Lin/z1;->f:Ljava/lang/Object;

    .line 863
    .line 864
    new-instance v3, Lbb/g0;

    .line 865
    .line 866
    const/4 v1, 0x0

    .line 867
    const/4 v5, 0x0

    .line 868
    invoke-direct {v3, v10, v1, v5}, Lbb/g0;-><init>(Lin/z1;IB)V

    .line 869
    .line 870
    .line 871
    invoke-virtual {v2}, Llp/lg;->c()Ljava/lang/String;

    .line 872
    .line 873
    .line 874
    move-result-object v5

    .line 875
    sget-object v10, Lfv/l;->d:Lfv/l;

    .line 876
    .line 877
    new-instance v1, Ld6/z0;

    .line 878
    .line 879
    const/4 v6, 0x3

    .line 880
    invoke-direct/range {v1 .. v6}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 881
    .line 882
    .line 883
    invoke-virtual {v10, v1}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 884
    .line 885
    .line 886
    goto/16 :goto_8

    .line 887
    .line 888
    :cond_12
    invoke-virtual {v0, v4}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    :cond_13
    return-void

    .line 892
    :pswitch_b
    invoke-direct {p0}, Llr/b;->b()V

    .line 893
    .line 894
    .line 895
    return-void

    .line 896
    :pswitch_c
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 897
    .line 898
    check-cast v0, Lis/b;

    .line 899
    .line 900
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 901
    .line 902
    check-cast p0, Llo/l;

    .line 903
    .line 904
    iget-object v0, v0, Lis/b;->b:Ljava/lang/Object;

    .line 905
    .line 906
    if-nez v0, :cond_14

    .line 907
    .line 908
    invoke-interface {p0}, Llo/l;->Q()V

    .line 909
    .line 910
    .line 911
    goto :goto_c

    .line 912
    :cond_14
    :try_start_3
    invoke-interface {p0, v0}, Llo/l;->q(Ljava/lang/Object;)V
    :try_end_3
    .catch Ljava/lang/RuntimeException; {:try_start_3 .. :try_end_3} :catch_3

    .line 913
    .line 914
    .line 915
    :goto_c
    return-void

    .line 916
    :catch_3
    move-exception v0

    .line 917
    invoke-interface {p0}, Llo/l;->Q()V

    .line 918
    .line 919
    .line 920
    throw v0

    .line 921
    :pswitch_d
    invoke-direct {p0}, Llr/b;->a()V

    .line 922
    .line 923
    .line 924
    return-void

    .line 925
    :pswitch_e
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 926
    .line 927
    move-object v2, v0

    .line 928
    check-cast v2, Lka/h;

    .line 929
    .line 930
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 931
    .line 932
    check-cast p0, Ljava/util/ArrayList;

    .line 933
    .line 934
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 935
    .line 936
    .line 937
    move-result-object v0

    .line 938
    :cond_15
    :goto_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 939
    .line 940
    .line 941
    move-result v1

    .line 942
    if-eqz v1, :cond_19

    .line 943
    .line 944
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 945
    .line 946
    .line 947
    move-result-object v1

    .line 948
    move-object v3, v1

    .line 949
    check-cast v3, Lka/f;

    .line 950
    .line 951
    iget-object v7, v2, Lka/h;->r:Ljava/util/ArrayList;

    .line 952
    .line 953
    iget-wide v8, v2, Lka/c0;->f:J

    .line 954
    .line 955
    iget-object v1, v3, Lka/f;->a:Lka/v0;

    .line 956
    .line 957
    const/4 v4, 0x0

    .line 958
    if-nez v1, :cond_16

    .line 959
    .line 960
    move-object v5, v4

    .line 961
    goto :goto_e

    .line 962
    :cond_16
    iget-object v1, v1, Lka/v0;->a:Landroid/view/View;

    .line 963
    .line 964
    move-object v5, v1

    .line 965
    :goto_e
    iget-object v1, v3, Lka/f;->b:Lka/v0;

    .line 966
    .line 967
    if-eqz v1, :cond_17

    .line 968
    .line 969
    iget-object v4, v1, Lka/v0;->a:Landroid/view/View;

    .line 970
    .line 971
    :cond_17
    move-object v10, v4

    .line 972
    const/4 v11, 0x0

    .line 973
    if-eqz v5, :cond_18

    .line 974
    .line 975
    invoke-virtual {v5}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 976
    .line 977
    .line 978
    move-result-object v1

    .line 979
    invoke-virtual {v1, v8, v9}, Landroid/view/ViewPropertyAnimator;->setDuration(J)Landroid/view/ViewPropertyAnimator;

    .line 980
    .line 981
    .line 982
    move-result-object v4

    .line 983
    iget-object v1, v3, Lka/f;->a:Lka/v0;

    .line 984
    .line 985
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 986
    .line 987
    .line 988
    iget v1, v3, Lka/f;->e:I

    .line 989
    .line 990
    iget v6, v3, Lka/f;->c:I

    .line 991
    .line 992
    sub-int/2addr v1, v6

    .line 993
    int-to-float v1, v1

    .line 994
    invoke-virtual {v4, v1}, Landroid/view/ViewPropertyAnimator;->translationX(F)Landroid/view/ViewPropertyAnimator;

    .line 995
    .line 996
    .line 997
    iget v1, v3, Lka/f;->f:I

    .line 998
    .line 999
    iget v6, v3, Lka/f;->d:I

    .line 1000
    .line 1001
    sub-int/2addr v1, v6

    .line 1002
    int-to-float v1, v1

    .line 1003
    invoke-virtual {v4, v1}, Landroid/view/ViewPropertyAnimator;->translationY(F)Landroid/view/ViewPropertyAnimator;

    .line 1004
    .line 1005
    .line 1006
    invoke-virtual {v4, v11}, Landroid/view/ViewPropertyAnimator;->alpha(F)Landroid/view/ViewPropertyAnimator;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v12

    .line 1010
    new-instance v1, Lka/e;

    .line 1011
    .line 1012
    const/4 v6, 0x0

    .line 1013
    invoke-direct/range {v1 .. v6}, Lka/e;-><init>(Lka/h;Lka/f;Landroid/view/ViewPropertyAnimator;Landroid/view/View;I)V

    .line 1014
    .line 1015
    .line 1016
    invoke-virtual {v12, v1}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v1

    .line 1020
    invoke-virtual {v1}, Landroid/view/ViewPropertyAnimator;->start()V

    .line 1021
    .line 1022
    .line 1023
    :cond_18
    if-eqz v10, :cond_15

    .line 1024
    .line 1025
    invoke-virtual {v10}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 1026
    .line 1027
    .line 1028
    move-result-object v4

    .line 1029
    iget-object v1, v3, Lka/f;->b:Lka/v0;

    .line 1030
    .line 1031
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1032
    .line 1033
    .line 1034
    invoke-virtual {v4, v11}, Landroid/view/ViewPropertyAnimator;->translationX(F)Landroid/view/ViewPropertyAnimator;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v1

    .line 1038
    invoke-virtual {v1, v11}, Landroid/view/ViewPropertyAnimator;->translationY(F)Landroid/view/ViewPropertyAnimator;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v1

    .line 1042
    invoke-virtual {v1, v8, v9}, Landroid/view/ViewPropertyAnimator;->setDuration(J)Landroid/view/ViewPropertyAnimator;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v1

    .line 1046
    const/high16 v5, 0x3f800000    # 1.0f

    .line 1047
    .line 1048
    invoke-virtual {v1, v5}, Landroid/view/ViewPropertyAnimator;->alpha(F)Landroid/view/ViewPropertyAnimator;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v7

    .line 1052
    new-instance v1, Lka/e;

    .line 1053
    .line 1054
    const/4 v6, 0x1

    .line 1055
    move-object v5, v10

    .line 1056
    invoke-direct/range {v1 .. v6}, Lka/e;-><init>(Lka/h;Lka/f;Landroid/view/ViewPropertyAnimator;Landroid/view/View;I)V

    .line 1057
    .line 1058
    .line 1059
    invoke-virtual {v7, v1}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v1

    .line 1063
    invoke-virtual {v1}, Landroid/view/ViewPropertyAnimator;->start()V

    .line 1064
    .line 1065
    .line 1066
    goto/16 :goto_d

    .line 1067
    .line 1068
    :cond_19
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 1069
    .line 1070
    .line 1071
    iget-object v0, v2, Lka/h;->n:Ljava/util/ArrayList;

    .line 1072
    .line 1073
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 1074
    .line 1075
    .line 1076
    return-void

    .line 1077
    :pswitch_f
    const/4 v1, 0x0

    .line 1078
    :try_start_4
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1079
    .line 1080
    check-cast v0, Lk0/b;

    .line 1081
    .line 1082
    iget-object v2, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1083
    .line 1084
    check-cast v2, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 1085
    .line 1086
    invoke-static {v2}, Lk0/h;->b(Ljava/util/concurrent/Future;)Ljava/lang/Object;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v2

    .line 1090
    iget-object v0, v0, Lk0/d;->e:Ly4/h;

    .line 1091
    .line 1092
    if-eqz v0, :cond_1a

    .line 1093
    .line 1094
    invoke-virtual {v0, v2}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_4
    .catch Ljava/util/concurrent/CancellationException; {:try_start_4 .. :try_end_4} :catch_5
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_4 .. :try_end_4} :catch_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 1095
    .line 1096
    .line 1097
    :cond_1a
    :goto_f
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1098
    .line 1099
    check-cast p0, Lk0/b;

    .line 1100
    .line 1101
    iput-object v1, p0, Lk0/b;->j:Lcom/google/common/util/concurrent/ListenableFuture;

    .line 1102
    .line 1103
    goto :goto_10

    .line 1104
    :catchall_0
    move-exception v0

    .line 1105
    goto :goto_11

    .line 1106
    :catch_4
    move-exception v0

    .line 1107
    :try_start_5
    iget-object v2, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1108
    .line 1109
    check-cast v2, Lk0/b;

    .line 1110
    .line 1111
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v0

    .line 1115
    iget-object v2, v2, Lk0/d;->e:Ly4/h;

    .line 1116
    .line 1117
    if-eqz v2, :cond_1a

    .line 1118
    .line 1119
    invoke-virtual {v2, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 1120
    .line 1121
    .line 1122
    goto :goto_f

    .line 1123
    :catch_5
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1124
    .line 1125
    check-cast v0, Lk0/b;

    .line 1126
    .line 1127
    const/4 v2, 0x0

    .line 1128
    invoke-virtual {v0, v2}, Lk0/b;->cancel(Z)Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 1129
    .line 1130
    .line 1131
    goto :goto_f

    .line 1132
    :goto_10
    return-void

    .line 1133
    :goto_11
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1134
    .line 1135
    check-cast p0, Lk0/b;

    .line 1136
    .line 1137
    iput-object v1, p0, Lk0/b;->j:Lcom/google/common/util/concurrent/ListenableFuture;

    .line 1138
    .line 1139
    throw v0

    .line 1140
    :pswitch_10
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1141
    .line 1142
    move-object v1, v0

    .line 1143
    check-cast v1, Lio/m;

    .line 1144
    .line 1145
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1146
    .line 1147
    check-cast p0, Lio/n;

    .line 1148
    .line 1149
    iget p0, p0, Lio/n;->a:I

    .line 1150
    .line 1151
    const-string v0, "Timing out request: "

    .line 1152
    .line 1153
    monitor-enter v1

    .line 1154
    :try_start_6
    iget-object v2, v1, Lio/m;->e:Landroid/util/SparseArray;

    .line 1155
    .line 1156
    invoke-virtual {v2, p0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v2

    .line 1160
    check-cast v2, Lio/n;

    .line 1161
    .line 1162
    if-eqz v2, :cond_1b

    .line 1163
    .line 1164
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1165
    .line 1166
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1167
    .line 1168
    .line 1169
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1170
    .line 1171
    .line 1172
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1173
    .line 1174
    .line 1175
    move-result-object v0

    .line 1176
    const-string v3, "MessengerIpcClient"

    .line 1177
    .line 1178
    invoke-static {v3, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1179
    .line 1180
    .line 1181
    iget-object v0, v1, Lio/m;->e:Landroid/util/SparseArray;

    .line 1182
    .line 1183
    invoke-virtual {v0, p0}, Landroid/util/SparseArray;->remove(I)V

    .line 1184
    .line 1185
    .line 1186
    const-string p0, "Timed out waiting for response"

    .line 1187
    .line 1188
    new-instance v0, Lb0/l;

    .line 1189
    .line 1190
    const/4 v3, 0x0

    .line 1191
    invoke-direct {v0, p0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 1192
    .line 1193
    .line 1194
    invoke-virtual {v2, v0}, Lio/n;->b(Lb0/l;)V

    .line 1195
    .line 1196
    .line 1197
    invoke-virtual {v1}, Lio/m;->c()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 1198
    .line 1199
    .line 1200
    :cond_1b
    monitor-exit v1

    .line 1201
    goto :goto_12

    .line 1202
    :catchall_1
    move-exception v0

    .line 1203
    move-object p0, v0

    .line 1204
    goto :goto_13

    .line 1205
    :goto_12
    return-void

    .line 1206
    :goto_13
    :try_start_7
    monitor-exit v1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 1207
    throw p0

    .line 1208
    :pswitch_11
    :try_start_8
    invoke-virtual {p0}, Llr/b;->e()V
    :try_end_8
    .catch Ljava/lang/Error; {:try_start_8 .. :try_end_8} :catch_6

    .line 1209
    .line 1210
    .line 1211
    return-void

    .line 1212
    :catch_6
    move-exception v0

    .line 1213
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1214
    .line 1215
    check-cast v1, Lhs/k;

    .line 1216
    .line 1217
    iget-object v1, v1, Lhs/k;->e:Ljava/util/ArrayDeque;

    .line 1218
    .line 1219
    monitor-enter v1

    .line 1220
    :try_start_9
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1221
    .line 1222
    check-cast p0, Lhs/k;

    .line 1223
    .line 1224
    const/4 v2, 0x1

    .line 1225
    iput v2, p0, Lhs/k;->f:I

    .line 1226
    .line 1227
    monitor-exit v1
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 1228
    throw v0

    .line 1229
    :catchall_2
    move-exception v0

    .line 1230
    move-object p0, v0

    .line 1231
    :try_start_a
    monitor-exit v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 1232
    throw p0

    .line 1233
    :pswitch_12
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v0

    .line 1237
    sget-object v1, Lgb/a;->e:Ljava/lang/String;

    .line 1238
    .line 1239
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1240
    .line 1241
    const-string v3, "Scheduling work "

    .line 1242
    .line 1243
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1244
    .line 1245
    .line 1246
    iget-object v3, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1247
    .line 1248
    check-cast v3, Lmb/o;

    .line 1249
    .line 1250
    iget-object v4, v3, Lmb/o;->a:Ljava/lang/String;

    .line 1251
    .line 1252
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1253
    .line 1254
    .line 1255
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1256
    .line 1257
    .line 1258
    move-result-object v2

    .line 1259
    invoke-virtual {v0, v1, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 1260
    .line 1261
    .line 1262
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1263
    .line 1264
    check-cast p0, Lgb/a;

    .line 1265
    .line 1266
    iget-object p0, p0, Lgb/a;->a:Lgb/c;

    .line 1267
    .line 1268
    filled-new-array {v3}, [Lmb/o;

    .line 1269
    .line 1270
    .line 1271
    move-result-object v0

    .line 1272
    invoke-virtual {p0, v0}, Lgb/c;->a([Lmb/o;)V

    .line 1273
    .line 1274
    .line 1275
    return-void

    .line 1276
    :pswitch_13
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1277
    .line 1278
    check-cast v0, Leb/j0;

    .line 1279
    .line 1280
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1281
    .line 1282
    check-cast p0, Laq/k;

    .line 1283
    .line 1284
    iget-object v1, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 1285
    .line 1286
    check-cast v1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 1287
    .line 1288
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 1289
    .line 1290
    .line 1291
    move-result v1

    .line 1292
    const/4 v2, 0x0

    .line 1293
    if-ltz v1, :cond_1c

    .line 1294
    .line 1295
    const/4 v3, 0x1

    .line 1296
    goto :goto_14

    .line 1297
    :cond_1c
    move v3, v2

    .line 1298
    :goto_14
    invoke-static {v3}, Lno/c0;->k(Z)V

    .line 1299
    .line 1300
    .line 1301
    if-nez v1, :cond_1d

    .line 1302
    .line 1303
    invoke-virtual {v0}, Leb/j0;->D()V

    .line 1304
    .line 1305
    .line 1306
    iget-object v0, v0, Leb/j0;->g:Ljava/lang/Object;

    .line 1307
    .line 1308
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 1309
    .line 1310
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 1311
    .line 1312
    .line 1313
    :cond_1d
    sget-object v0, Lip/n;->d:Ljava/util/HashMap;

    .line 1314
    .line 1315
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 1316
    .line 1317
    .line 1318
    sget-object v0, Lip/u;->a:Ljava/util/HashMap;

    .line 1319
    .line 1320
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 1321
    .line 1322
    .line 1323
    const/4 v0, 0x0

    .line 1324
    invoke-virtual {p0, v0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 1325
    .line 1326
    .line 1327
    return-void

    .line 1328
    :pswitch_14
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1329
    .line 1330
    check-cast v0, Ljava/lang/ref/ReferenceQueue;

    .line 1331
    .line 1332
    :catch_7
    :goto_15
    iget-object v1, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1333
    .line 1334
    check-cast v1, Ljava/util/Set;

    .line 1335
    .line 1336
    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    .line 1337
    .line 1338
    .line 1339
    move-result v1

    .line 1340
    if-nez v1, :cond_1f

    .line 1341
    .line 1342
    :try_start_b
    invoke-virtual {v0}, Ljava/lang/ref/ReferenceQueue;->remove()Ljava/lang/ref/Reference;

    .line 1343
    .line 1344
    .line 1345
    move-result-object v1

    .line 1346
    check-cast v1, Lfv/k;

    .line 1347
    .line 1348
    iget-object v2, v1, Lfv/k;->a:Ljava/util/Set;

    .line 1349
    .line 1350
    invoke-interface {v2, v1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 1351
    .line 1352
    .line 1353
    move-result v2

    .line 1354
    if-nez v2, :cond_1e

    .line 1355
    .line 1356
    goto :goto_15

    .line 1357
    :cond_1e
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->clear()V

    .line 1358
    .line 1359
    .line 1360
    iget-object v1, v1, Lfv/k;->b:Lfv/j;

    .line 1361
    .line 1362
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_b
    .catch Ljava/lang/InterruptedException; {:try_start_b .. :try_end_b} :catch_7

    .line 1363
    .line 1364
    .line 1365
    goto :goto_15

    .line 1366
    :cond_1f
    return-void

    .line 1367
    :pswitch_15
    const/4 v0, 0x0

    .line 1368
    move v1, v0

    .line 1369
    :cond_20
    :try_start_c
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1370
    .line 1371
    check-cast v0, Ljava/lang/Runnable;

    .line 1372
    .line 1373
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 1374
    .line 1375
    .line 1376
    goto :goto_16

    .line 1377
    :catchall_3
    move-exception v0

    .line 1378
    :try_start_d
    sget-object v2, Lpx0/h;->d:Lpx0/h;

    .line 1379
    .line 1380
    invoke-static {v2, v0}, Lvy0/e0;->y(Lpx0/g;Ljava/lang/Throwable;)V

    .line 1381
    .line 1382
    .line 1383
    :goto_16
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1384
    .line 1385
    check-cast v0, Laz0/g;

    .line 1386
    .line 1387
    invoke-virtual {v0}, Laz0/g;->e0()Ljava/lang/Runnable;

    .line 1388
    .line 1389
    .line 1390
    move-result-object v0

    .line 1391
    if-nez v0, :cond_21

    .line 1392
    .line 1393
    goto :goto_17

    .line 1394
    :cond_21
    iput-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1395
    .line 1396
    add-int/lit8 v1, v1, 0x1

    .line 1397
    .line 1398
    const/16 v0, 0x10

    .line 1399
    .line 1400
    if-lt v1, v0, :cond_20

    .line 1401
    .line 1402
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1403
    .line 1404
    check-cast v0, Laz0/g;

    .line 1405
    .line 1406
    iget-object v2, v0, Laz0/g;->f:Lvy0/x;

    .line 1407
    .line 1408
    invoke-static {v2, v0}, Laz0/b;->j(Lvy0/x;Lpx0/g;)Z

    .line 1409
    .line 1410
    .line 1411
    move-result v0

    .line 1412
    if-eqz v0, :cond_20

    .line 1413
    .line 1414
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1415
    .line 1416
    check-cast v0, Laz0/g;

    .line 1417
    .line 1418
    iget-object v1, v0, Laz0/g;->f:Lvy0/x;

    .line 1419
    .line 1420
    invoke-static {v1, v0, p0}, Laz0/b;->i(Lvy0/x;Lpx0/g;Ljava/lang/Runnable;)V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 1421
    .line 1422
    .line 1423
    :goto_17
    return-void

    .line 1424
    :catchall_4
    move-exception v0

    .line 1425
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1426
    .line 1427
    check-cast p0, Laz0/g;

    .line 1428
    .line 1429
    iget-object v1, p0, Laz0/g;->i:Ljava/lang/Object;

    .line 1430
    .line 1431
    monitor-enter v1

    .line 1432
    :try_start_e
    sget-object v2, Laz0/g;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 1433
    .line 1434
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_5

    .line 1435
    .line 1436
    .line 1437
    monitor-exit v1

    .line 1438
    throw v0

    .line 1439
    :catchall_5
    move-exception v0

    .line 1440
    move-object p0, v0

    .line 1441
    monitor-exit v1

    .line 1442
    throw p0

    .line 1443
    :pswitch_16
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1444
    .line 1445
    move-object v1, v0

    .line 1446
    check-cast v1, Laq/q;

    .line 1447
    .line 1448
    :try_start_f
    iget-object v0, v1, Laq/q;->f:Ljava/lang/Object;

    .line 1449
    .line 1450
    check-cast v0, Laq/i;

    .line 1451
    .line 1452
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1453
    .line 1454
    check-cast p0, Laq/j;

    .line 1455
    .line 1456
    invoke-virtual {p0}, Laq/j;->g()Ljava/lang/Object;

    .line 1457
    .line 1458
    .line 1459
    move-result-object p0

    .line 1460
    invoke-interface {v0, p0}, Laq/i;->g(Ljava/lang/Object;)Laq/t;

    .line 1461
    .line 1462
    .line 1463
    move-result-object p0
    :try_end_f
    .catch Laq/h; {:try_start_f .. :try_end_f} :catch_9
    .catch Ljava/util/concurrent/CancellationException; {:try_start_f .. :try_end_f} :catch_a
    .catch Ljava/lang/Exception; {:try_start_f .. :try_end_f} :catch_8

    .line 1464
    if-nez p0, :cond_22

    .line 1465
    .line 1466
    new-instance p0, Ljava/lang/NullPointerException;

    .line 1467
    .line 1468
    const-string v0, "Continuation returned null"

    .line 1469
    .line 1470
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 1471
    .line 1472
    .line 1473
    invoke-virtual {v1, p0}, Laq/q;->onFailure(Ljava/lang/Exception;)V

    .line 1474
    .line 1475
    .line 1476
    goto :goto_1a

    .line 1477
    :cond_22
    sget-object v0, Laq/l;->b:Lj0/a;

    .line 1478
    .line 1479
    invoke-virtual {p0, v0, v1}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 1480
    .line 1481
    .line 1482
    invoke-virtual {p0, v0, v1}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 1483
    .line 1484
    .line 1485
    invoke-virtual {p0, v0, v1}, Laq/t;->a(Ljava/util/concurrent/Executor;Laq/d;)Laq/t;

    .line 1486
    .line 1487
    .line 1488
    goto :goto_1a

    .line 1489
    :catch_8
    move-exception v0

    .line 1490
    move-object p0, v0

    .line 1491
    goto :goto_18

    .line 1492
    :catch_9
    move-exception v0

    .line 1493
    move-object p0, v0

    .line 1494
    goto :goto_19

    .line 1495
    :goto_18
    invoke-virtual {v1, p0}, Laq/q;->onFailure(Ljava/lang/Exception;)V

    .line 1496
    .line 1497
    .line 1498
    goto :goto_1a

    .line 1499
    :catch_a
    invoke-virtual {v1}, Laq/q;->s()V

    .line 1500
    .line 1501
    .line 1502
    goto :goto_1a

    .line 1503
    :goto_19
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1504
    .line 1505
    .line 1506
    move-result-object v0

    .line 1507
    instance-of v0, v0, Ljava/lang/Exception;

    .line 1508
    .line 1509
    if-eqz v0, :cond_23

    .line 1510
    .line 1511
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1512
    .line 1513
    .line 1514
    move-result-object p0

    .line 1515
    check-cast p0, Ljava/lang/Exception;

    .line 1516
    .line 1517
    invoke-virtual {v1, p0}, Laq/q;->onFailure(Ljava/lang/Exception;)V

    .line 1518
    .line 1519
    .line 1520
    goto :goto_1a

    .line 1521
    :cond_23
    invoke-virtual {v1, p0}, Laq/q;->onFailure(Ljava/lang/Exception;)V

    .line 1522
    .line 1523
    .line 1524
    :goto_1a
    return-void

    .line 1525
    :pswitch_17
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1526
    .line 1527
    check-cast v0, Laq/q;

    .line 1528
    .line 1529
    iget-object v1, v0, Laq/q;->f:Ljava/lang/Object;

    .line 1530
    .line 1531
    monitor-enter v1

    .line 1532
    :try_start_10
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1533
    .line 1534
    check-cast v0, Laq/q;

    .line 1535
    .line 1536
    iget-object v0, v0, Laq/q;->g:Ljava/lang/Object;

    .line 1537
    .line 1538
    check-cast v0, Laq/f;

    .line 1539
    .line 1540
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1541
    .line 1542
    check-cast p0, Laq/j;

    .line 1543
    .line 1544
    invoke-virtual {p0}, Laq/j;->f()Ljava/lang/Exception;

    .line 1545
    .line 1546
    .line 1547
    move-result-object p0

    .line 1548
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 1549
    .line 1550
    .line 1551
    invoke-interface {v0, p0}, Laq/f;->onFailure(Ljava/lang/Exception;)V

    .line 1552
    .line 1553
    .line 1554
    monitor-exit v1

    .line 1555
    return-void

    .line 1556
    :catchall_6
    move-exception v0

    .line 1557
    move-object p0, v0

    .line 1558
    monitor-exit v1
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_6

    .line 1559
    throw p0

    .line 1560
    :pswitch_18
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1561
    .line 1562
    check-cast v0, Laq/o;

    .line 1563
    .line 1564
    iget-object v1, v0, Laq/o;->g:Laq/t;

    .line 1565
    .line 1566
    :try_start_11
    iget-object v2, v0, Laq/o;->f:Laq/b;

    .line 1567
    .line 1568
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1569
    .line 1570
    check-cast p0, Laq/j;

    .line 1571
    .line 1572
    invoke-interface {v2, p0}, Laq/b;->w(Laq/j;)Ljava/lang/Object;

    .line 1573
    .line 1574
    .line 1575
    move-result-object p0

    .line 1576
    check-cast p0, Laq/j;
    :try_end_11
    .catch Laq/h; {:try_start_11 .. :try_end_11} :catch_c
    .catch Ljava/lang/Exception; {:try_start_11 .. :try_end_11} :catch_b

    .line 1577
    .line 1578
    if-nez p0, :cond_24

    .line 1579
    .line 1580
    new-instance p0, Ljava/lang/NullPointerException;

    .line 1581
    .line 1582
    const-string v1, "Continuation returned null"

    .line 1583
    .line 1584
    invoke-direct {p0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 1585
    .line 1586
    .line 1587
    invoke-virtual {v0, p0}, Laq/o;->onFailure(Ljava/lang/Exception;)V

    .line 1588
    .line 1589
    .line 1590
    goto :goto_1d

    .line 1591
    :cond_24
    sget-object v1, Laq/l;->b:Lj0/a;

    .line 1592
    .line 1593
    invoke-virtual {p0, v1, v0}, Laq/j;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 1594
    .line 1595
    .line 1596
    invoke-virtual {p0, v1, v0}, Laq/j;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 1597
    .line 1598
    .line 1599
    invoke-virtual {p0, v1, v0}, Laq/j;->a(Ljava/util/concurrent/Executor;Laq/d;)Laq/t;

    .line 1600
    .line 1601
    .line 1602
    goto :goto_1d

    .line 1603
    :catch_b
    move-exception v0

    .line 1604
    move-object p0, v0

    .line 1605
    goto :goto_1b

    .line 1606
    :catch_c
    move-exception v0

    .line 1607
    move-object p0, v0

    .line 1608
    goto :goto_1c

    .line 1609
    :goto_1b
    invoke-virtual {v1, p0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1610
    .line 1611
    .line 1612
    goto :goto_1d

    .line 1613
    :goto_1c
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1614
    .line 1615
    .line 1616
    move-result-object v0

    .line 1617
    instance-of v0, v0, Ljava/lang/Exception;

    .line 1618
    .line 1619
    if-eqz v0, :cond_25

    .line 1620
    .line 1621
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1622
    .line 1623
    .line 1624
    move-result-object p0

    .line 1625
    check-cast p0, Ljava/lang/Exception;

    .line 1626
    .line 1627
    invoke-virtual {v1, p0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1628
    .line 1629
    .line 1630
    goto :goto_1d

    .line 1631
    :cond_25
    invoke-virtual {v1, p0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1632
    .line 1633
    .line 1634
    :goto_1d
    return-void

    .line 1635
    :pswitch_19
    iget-object v0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 1636
    .line 1637
    move-object v1, v0

    .line 1638
    check-cast v1, Lvp/y1;

    .line 1639
    .line 1640
    iget-object p0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 1641
    .line 1642
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 1643
    .line 1644
    :try_start_12
    invoke-static {p0}, Ln3/c;->a(Lcom/google/common/util/concurrent/ListenableFuture;)V
    :try_end_12
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_12 .. :try_end_12} :catch_d
    .catchall {:try_start_12 .. :try_end_12} :catchall_7

    .line 1645
    .line 1646
    .line 1647
    iget-object p0, v1, Lvp/y1;->f:Ljava/lang/Object;

    .line 1648
    .line 1649
    check-cast p0, Lvp/j2;

    .line 1650
    .line 1651
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 1652
    .line 1653
    .line 1654
    invoke-virtual {v1}, Lvp/y1;->X()V

    .line 1655
    .line 1656
    .line 1657
    const/4 v0, 0x0

    .line 1658
    iput-boolean v0, p0, Lvp/j2;->m:Z

    .line 1659
    .line 1660
    const/4 v0, 0x1

    .line 1661
    iput v0, p0, Lvp/j2;->n:I

    .line 1662
    .line 1663
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 1664
    .line 1665
    check-cast v0, Lvp/g1;

    .line 1666
    .line 1667
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 1668
    .line 1669
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 1670
    .line 1671
    .line 1672
    iget-object v0, v0, Lvp/p0;->q:Lvp/n0;

    .line 1673
    .line 1674
    iget-object v1, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 1675
    .line 1676
    check-cast v1, Lvp/o3;

    .line 1677
    .line 1678
    const-string v2, "Successfully registered trigger URI"

    .line 1679
    .line 1680
    iget-object v1, v1, Lvp/o3;->d:Ljava/lang/String;

    .line 1681
    .line 1682
    invoke-virtual {v0, v1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1683
    .line 1684
    .line 1685
    invoke-virtual {p0}, Lvp/j2;->z0()V

    .line 1686
    .line 1687
    .line 1688
    goto :goto_1e

    .line 1689
    :catchall_7
    move-exception v0

    .line 1690
    move-object p0, v0

    .line 1691
    invoke-virtual {v1, p0}, Lvp/y1;->y(Ljava/lang/Throwable;)V

    .line 1692
    .line 1693
    .line 1694
    goto :goto_1e

    .line 1695
    :catch_d
    move-exception v0

    .line 1696
    move-object p0, v0

    .line 1697
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1698
    .line 1699
    .line 1700
    move-result-object p0

    .line 1701
    invoke-virtual {v1, p0}, Lvp/y1;->y(Ljava/lang/Throwable;)V

    .line 1702
    .line 1703
    .line 1704
    :goto_1e
    return-void

    .line 1705
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Llr/b;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :sswitch_0
    iget-object v0, p0, Llr/b;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/Runnable;

    .line 14
    .line 15
    const-string v1, "}"

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    new-instance p0, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v2, "SequentialExecutorWorker{running="

    .line 22
    .line 23
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v2, "SequentialExecutorWorker{state="

    .line 40
    .line 41
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lhs/k;

    .line 47
    .line 48
    iget p0, p0, Lhs/k;->f:I

    .line 49
    .line 50
    const/4 v2, 0x1

    .line 51
    if-eq p0, v2, :cond_4

    .line 52
    .line 53
    const/4 v2, 0x2

    .line 54
    if-eq p0, v2, :cond_3

    .line 55
    .line 56
    const/4 v2, 0x3

    .line 57
    if-eq p0, v2, :cond_2

    .line 58
    .line 59
    const/4 v2, 0x4

    .line 60
    if-eq p0, v2, :cond_1

    .line 61
    .line 62
    const-string p0, "null"

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    const-string p0, "RUNNING"

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    const-string p0, "QUEUED"

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_3
    const-string p0, "QUEUING"

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_4
    const-string p0, "IDLE"

    .line 75
    .line 76
    :goto_0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    :goto_1
    return-object p0

    .line 87
    :sswitch_1
    new-instance v0, Lgw0/c;

    .line 88
    .line 89
    const-class v1, Llr/b;

    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-direct {v0, v1}, Lgw0/c;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Llr/b;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Lvp/y1;

    .line 101
    .line 102
    new-instance v1, Lvp/y1;

    .line 103
    .line 104
    const/4 v2, 0x7

    .line 105
    const/4 v3, 0x0

    .line 106
    invoke-direct {v1, v2, v3}, Lvp/y1;-><init>(IZ)V

    .line 107
    .line 108
    .line 109
    iget-object v2, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v2, Lvp/y1;

    .line 112
    .line 113
    iput-object v1, v2, Lvp/y1;->f:Ljava/lang/Object;

    .line 114
    .line 115
    iput-object v1, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 116
    .line 117
    iput-object p0, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 118
    .line 119
    invoke-virtual {v0}, Lgw0/c;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0

    .line 124
    nop

    .line 125
    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_1
        0x8 -> :sswitch_0
    .end sparse-switch
.end method
